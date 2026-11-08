"""
meshguard.models - Core Data Models for WireGuard Mesh Topologies and Auditing.

This module establishes the canonical data structures for describing:
1. Low-level WireGuard interface configurations ([Interface] and [Peer] blocks).
2. High-level multi-node mesh blueprints (Full Mesh vs. Hub-and-Spoke).
3. Subnet collision detection results and cryptographic audit findings.

===============================================================================
THE ARCHITECTURAL PRINCIPLE OF CRYPTOKEY ROUTING:
===============================================================================
Traditional VPNs (IPsec, OpenVPN) separate the cryptographic tunnel from the IP
routing table. WireGuard unifies them into a single concept: "Cryptokey Routing".

In Cryptokey Routing:
1. Outbound routing (Transmission):
   When a packet enters the WireGuard interface (e.g. `wg0`), the kernel inspects
   the destination IP address against the `AllowedIPs` list of every configured peer.
   WireGuard maintains a specialized Radix trie (longest-prefix match).
   - If a matching peer is found, the packet is encrypted using that peer's
     Curve25519 public key and transmitted via UDP to that peer's `Endpoint`.
   - If no peer matches, the packet is dropped with ICMP Destination Unreachable.

2. Inbound routing (Reception & Anti-Spoofing):
   When a UDP packet arrives on the WireGuard listening port:
   - WireGuard decrypts the payload using the local private key and authenticated
     peer public key.
   - The kernel extracts the INNER source IP address of the unencrypted packet.
   - WireGuard verifies that the inner source IP is covered by that peer's
     `AllowedIPs` trie.
   - If it matches, the packet is accepted and passed into the OS network stack.
   - If it does NOT match, the packet is silently dropped! This provides built-in,
     kernel-level cryptographic anti-spoofing without needing iptables rp_filter.

CRITICAL CONSEQUENCE:
Because each destination IP must map deterministically to exactly ONE peer for
outbound encryption, TWO PEERS ON THE SAME INTERFACE CANNOT HAVE OVERLAPPING
ALLOWED IPS! Overlapping subnets result in packet blackholing or silent route
hijacking. This module and the associated auditor enforce this invariant.
"""

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from typing import List, Optional, Union, Dict, Any


class AuditSeverity(str, Enum):
    """
    Severity rating for configuration and network topology audit findings.

    CRITICAL: Definite breakage, route hijacking, packet loss, or fatal syntax error.
    ERROR:    Protocol violation (e.g. invalid key, MTU < 1280 breaking IPv6).
    WARNING:  Suboptimal configuration (e.g. MTU 1500 causing PMTU blackholes, NAT without keepalive).
    INFO:     Advisory recommendation or informational architecture insight.
    """
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TopologyType(str, Enum):
    """
    Topology models supported by the mesh generator.

    FULL_MESH:
        Every node connects directly to every other node with a known endpoint.
        Provides minimal latency (O(1) hops) and no single point of failure.
        Edges scale as N * (N - 1) / 2.

    HUB_AND_SPOKE:
        Central hub(s) with static public endpoints relay traffic between spoke nodes.
        Spoke nodes do not need open incoming firewall ports or public IP addresses.
        Ideal for NAT/CGNAT environments and cloud-to-edge architectures.
    """
    FULL_MESH = "full_mesh"
    HUB_AND_SPOKE = "hub_and_spoke"


@dataclass
class PeerConfig:
    """
    Represents a single [Peer] section in a WireGuard configuration file.

    Attributes:
        public_key: 44-character Base64 Curve25519 public key of the remote peer.
        allowed_ips: List of IPv4/IPv6 networks routed to/from this peer (CIDR strings).
        endpoint: Optional remote UDP socket address ("hostname:port" or "ip:port").
        preshared_key: Optional 44-character Base64 symmetric 256-bit PSK for post-quantum defense.
        persistent_keepalive: Seconds between dummy keepalive packets (typically 25s for NAT traversal).
        comment: Human-readable identifier or node name for configuration self-documentation.
    """
    public_key: str
    allowed_ips: List[str]
    endpoint: Optional[str] = None
    preshared_key: Optional[str] = None
    persistent_keepalive: Optional[int] = None
    comment: Optional[str] = None

    def to_wg_quick_block(self) -> str:
        """
        Serializes this peer into a wg-quick(8) compatible [Peer] block.
        """
        lines = []
        if self.comment:
            lines.append(f"# Node: {self.comment}")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {self.public_key}")

        if self.preshared_key:
            lines.append(f"PresharedKey = {self.preshared_key}")

        if self.endpoint:
            lines.append(f"Endpoint = {self.endpoint}")

        if self.allowed_ips:
            lines.append(f"AllowedIPs = {', '.join(self.allowed_ips)}")

        if self.persistent_keepalive is not None:
            lines.append(f"PersistentKeepalive = {self.persistent_keepalive}")

        return "\n".join(lines)


@dataclass
class InterfaceConfig:
    """
    Represents the [Interface] section of a WireGuard configuration file.

    Attributes:
        private_key: 44-character Base64 Curve25519 private key of the local node.
        addresses: List of local overlay IP addresses assigned to this interface (CIDR notation).
        listen_port: UDP port on which WireGuard listens for incoming encrypted handshakes/data.
        mtu: Maximum Transmission Unit in bytes (default 1420 to prevent UDP encapsulation fragmentation).
        dns: Optional DNS servers to inject into system resolver while interface is active.
        pre_up: Commands executed before bringing the interface up.
        post_up: Commands executed after bringing the interface up (e.g. iptables NAT rules).
        pre_down: Commands executed before bringing the interface down.
        post_down: Commands executed after bringing the interface down.
        table: Routing table handling ('auto', 'off', or routing table number).
    """
    private_key: str
    addresses: List[str]
    listen_port: Optional[int] = 51820
    mtu: Optional[int] = 1420
    dns: List[str] = field(default_factory=list)
    pre_up: List[str] = field(default_factory=list)
    post_up: List[str] = field(default_factory=list)
    pre_down: List[str] = field(default_factory=list)
    post_down: List[str] = field(default_factory=list)
    table: Optional[str] = None

    def to_wg_quick_block(self) -> str:
        """
        Serializes the local interface settings into a wg-quick [Interface] section.
        """
        lines = ["[Interface]"]
        lines.append(f"PrivateKey = {self.private_key}")

        for addr in self.addresses:
            lines.append(f"Address = {addr}")

        if self.listen_port is not None:
            lines.append(f"ListenPort = {self.listen_port}")

        if self.mtu is not None:
            lines.append(f"MTU = {self.mtu}")

        if self.dns:
            lines.append(f"DNS = {', '.join(self.dns)}")

        if self.table:
            lines.append(f"Table = {self.table}")

        for cmd in self.pre_up:
            lines.append(f"PreUp = {cmd}")
        for cmd in self.post_up:
            lines.append(f"PostUp = {cmd}")
        for cmd in self.pre_down:
            lines.append(f"PreDown = {cmd}")
        for cmd in self.post_down:
            lines.append(f"PostDown = {cmd}")

        return "\n".join(lines)


@dataclass
class WireGuardConfig:
    """
    Represents an entire WireGuard configuration file (interface + peers).
    """
    interface: InterfaceConfig
    peers: List[PeerConfig] = field(default_factory=list)

    def to_wg_quick(self) -> str:
        """
        Converts this configuration object into standard wg-quick(8) configuration file text.
        """
        blocks = [self.interface.to_wg_quick_block()]
        for peer in self.peers:
            blocks.append(peer.to_wg_quick_block())
        return "\n\n".join(blocks) + "\n"

    def to_systemd_networkd(self, interface_name: str = "wg0") -> Dict[str, str]:
        """
        Generates native systemd-networkd .netdev and .network files.

        Returns:
            Dictionary containing:
            - "{interface_name}.netdev": WireGuard virtual device definition.
            - "{interface_name}.network": IP address assignment and routing rules.
        """
        netdev_lines = [
            "# systemd-networkd virtual network device definition",
            "[NetDev]",
            f"Name={interface_name}",
            "Kind=wireguard",
            "",
            "[WireGuard]",
            f"PrivateKey={self.interface.private_key}",
        ]
        if self.interface.listen_port:
            netdev_lines.append(f"ListenPort={self.interface.listen_port}")

        for peer in self.peers:
            netdev_lines.append("")
            netdev_lines.append("[WireGuardPeer]")
            netdev_lines.append(f"PublicKey={peer.public_key}")
            if peer.preshared_key:
                netdev_lines.append(f"PresharedKey={peer.preshared_key}")
            if peer.endpoint:
                netdev_lines.append(f"Endpoint={peer.endpoint}")
            for ip_str in peer.allowed_ips:
                netdev_lines.append(f"AllowedIPs={ip_str}")
            if peer.persistent_keepalive is not None:
                netdev_lines.append(f"PersistentKeepalive={peer.persistent_keepalive}")

        network_lines = [
            "# systemd-networkd interface network and address mapping",
            "[Match]",
            f"Name={interface_name}",
            "",
            "[Network]",
        ]
        for addr in self.interface.addresses:
            network_lines.append(f"Address={addr}")

        if self.interface.dns:
            for dns_ip in self.interface.dns:
                network_lines.append(f"DNS={dns_ip}")

        if self.interface.mtu:
            network_lines.append("")
            network_lines.append("[Link]")
            network_lines.append(f"MTUBytes={self.interface.mtu}")

        return {
            f"{interface_name}.netdev": "\n".join(netdev_lines) + "\n",
            f"{interface_name}.network": "\n".join(network_lines) + "\n",
        }


@dataclass
class Node:
    """
    High-level blueprint representation of a node participating in the WireGuard mesh.

    Attributes:
        name: Unique alphanumeric hostname/identifier (e.g. 'edge-router', 'laptop-ethan').
        mesh_ips: Virtual IP addresses within the overlay network (e.g. ['10.100.0.1/24']).
        endpoint: Publicly accessible UDP socket (e.g. 'vpn.twu.software:51820'). None if behind NAT.
        listen_port: UDP port on which this node binds (default 51820).
        public_key: 44-character Base64 Curve25519 public key.
        private_key: Optional local private key.
        preshared_key: Optional node-specific PSK.
        extra_allowed_ips: Additional non-mesh subnets advertised by this node (e.g. home LAN).
        is_hub: If True in HUB_AND_SPOKE topology, this node acts as a central relay.
        persistent_keepalive: Custom keepalive duration; defaults to 25 if node is behind NAT.
        mtu: Interface MTU (default 1420).
        dns: Custom DNS addresses for this node.
        post_up: PostUp firewall/routing scripts (e.g. iptables MASQUERADE for gateway nodes).
        post_down: PostDown teardown scripts.
    """
    name: str
    mesh_ips: List[str]
    public_key: str
    endpoint: Optional[str] = None
    listen_port: Optional[int] = 51820
    private_key: Optional[str] = None
    preshared_key: Optional[str] = None
    extra_allowed_ips: List[str] = field(default_factory=list)
    is_hub: bool = False
    persistent_keepalive: Optional[int] = None
    mtu: int = 1420
    dns: List[str] = field(default_factory=list)
    post_up: List[str] = field(default_factory=list)
    post_down: List[str] = field(default_factory=list)

    def get_all_routable_ips(self) -> List[str]:
        """
        Returns all IP addresses/subnets routed to this node:
        1. Its overlay mesh IPs stripped to single-host /32 or /128 CIDR masks.
        2. Any extra advertised subnets (LANs).
        """
        routable = []
        for ip_str in self.mesh_ips:
            try:
                interface = ipaddress.ip_interface(ip_str)
                # When configuring peers, AllowedIPs must route specifically to this host
                # (e.g. 10.100.0.1/32 or fd00::1/128), NOT the entire subnet /24
                # because the entire /24 is shared across all mesh participants.
                if interface.version == 4:
                    routable.append(f"{interface.ip}/32")
                else:
                    routable.append(f"{interface.ip}/128")
            except ValueError:
                routable.append(ip_str)

        routable.extend(self.extra_allowed_ips)
        return routable


@dataclass
class MeshConfig:
    """
    The top-level declarative blueprint of an entire WireGuard mesh.
    """
    network_name: str
    topology: TopologyType = TopologyType.FULL_MESH
    default_mtu: int = 1420
    default_port: int = 51820
    nodes: List[Node] = field(default_factory=list)
    global_preshared_key: Optional[str] = None

    def get_node(self, name: str) -> Optional[Node]:
        """Looks up a node by name."""
        for n in self.nodes:
            if n.name == name:
                return n
        return None


@dataclass
class AuditFinding:
    """
    Represents a specific issue discovered during network auditing.
    """
    rule_id: str
    severity: AuditSeverity
    title: str
    message: str
    node_or_file: str
    recommendation: str

    def to_display_string(self) -> str:
        """Formats the finding with clear visual severity indicators."""
        return (
            f"[{self.severity.value}] {self.rule_id}: {self.title}\n"
            f"  Target: {self.node_or_file}\n"
            f"  Detail: {self.message}\n"
            f"  Action: {self.recommendation}"
        )
