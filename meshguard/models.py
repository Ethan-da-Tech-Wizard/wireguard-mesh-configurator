"""
Program: WireGuard Mesh Configurator - Data Models & Architecture
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Core data models representing WireGuard interfaces, peers, mesh blueprints, network nodes, and audit findings with serialization to wg-quick and systemd-networkd formats.
"""

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## Dataclass decorator and field helper for clean, declarative data structures
from dataclasses import dataclass, field
## Enumeration class for strongly-typed severity and topology categories
from enum import Enum
## IP network manipulation module for CIDR math and host mask conversions
import ipaddress
## Type annotations for type checking and self-documenting APIs
from typing import List, Optional, Union, Dict, Any


class AuditSeverity(str, Enum):
    """
    Severity rating for configuration and network topology audit findings.

    CRITICAL: Definite breakage, route hijacking, packet loss, or fatal syntax error.
    ERROR:    Protocol violation (e.g. invalid key, MTU < 1280 breaking IPv6).
    WARNING:  Suboptimal configuration (e.g. MTU 1500 causing PMTU blackholes, NAT without keepalive).
    INFO:     Advisory recommendation or informational architecture insight.
    """
    ## Critical severity: prevents network operation or introduces route hijacking
    CRITICAL = "CRITICAL"
    ## Error severity: protocol violations or malformed configurations
    ERROR = "ERROR"
    ## Warning severity: operational hazards such as fragmentation or NAT timeout risks
    WARNING = "WARNING"
    ## Informational severity: optimization tips and non-breaking best practices
    INFO = "INFO"


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
    ## Decentralized peer-to-peer topology where all nodes connect directly
    FULL_MESH = "full_mesh"
    ## Star topology where traffic relays through designated central gateway nodes
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
    ## Public key of the remote peer (Curve25519, 32 bytes encoded in Base64)
    public_key: str
    ## List of subnets routed through this cryptographic peer (Cryptokey routing)
    allowed_ips: List[str]
    ## Remote socket endpoint (hostname or IP followed by UDP port)
    endpoint: Optional[str] = None
    ## Optional symmetric 256-bit preshared key for post-quantum forward secrecy
    preshared_key: Optional[str] = None
    ## Optional interval in seconds to send dummy authenticated packets for NAT hole maintenance
    persistent_keepalive: Optional[int] = None
    ## Optional human-readable node name or descriptive comment for configuration clarity
    comment: Optional[str] = None

    def to_wg_quick_block(self) -> str:
        """
        Serializes this peer into a wg-quick(8) compatible [Peer] block.
        """
        ## Accumulator list for generated configuration lines
        lines = []

        ## Prepend descriptive comment banner if present
        if self.comment:
            lines.append(f"# Node: {self.comment}")

        ## Emit standard WireGuard section header
        lines.append("[Peer]")

        ## Append mandatory peer public key
        lines.append(f"PublicKey = {self.public_key}")

        ## Append post-quantum preshared key if configured
        if self.preshared_key:
            lines.append(f"PresharedKey = {self.preshared_key}")

        ## Append remote UDP endpoint if known
        if self.endpoint:
            lines.append(f"Endpoint = {self.endpoint}")

        ## Append comma-delimited AllowedIPs routes
        if self.allowed_ips:
            lines.append(f"AllowedIPs = {', '.join(self.allowed_ips)}")

        ## Append NAT persistent keepalive interval if defined
        if self.persistent_keepalive is not None:
            lines.append(f"PersistentKeepalive = {self.persistent_keepalive}")

        ## Join accumulated lines with standard line breaks
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
    ## Local node private key (32 bytes Base64-encoded)
    private_key: str
    ## List of IP addresses assigned to the local interface in CIDR notation
    addresses: List[str]
    ## UDP port to bind for incoming traffic (standard default is 51820)
    listen_port: Optional[int] = 51820
    ## Interface MTU (1420 bytes default prevents fragmentation over 1500-byte underlays)
    mtu: Optional[int] = 1420
    ## Optional list of DNS server IP addresses to configure while tunnel is up
    dns: List[str] = field(default_factory=list)
    ## Shell commands executed prior to interface activation
    pre_up: List[str] = field(default_factory=list)
    ## Shell commands executed after interface activation (e.g. firewall/NAT setup)
    post_up: List[str] = field(default_factory=list)
    ## Shell commands executed prior to interface teardown
    pre_down: List[str] = field(default_factory=list)
    ## Shell commands executed after interface teardown (e.g. firewall cleanup)
    post_down: List[str] = field(default_factory=list)
    ## Custom routing table strategy (e.g. 'auto', 'off', or specific table ID)
    table: Optional[str] = None

    def to_wg_quick_block(self) -> str:
        """
        Serializes the local interface settings into a wg-quick [Interface] section.
        """
        ## Initialize lines array starting with the [Interface] header
        lines = ["[Interface]"]

        ## Append private key definition
        lines.append(f"PrivateKey = {self.private_key}")

        ## Append each overlay IP address assigned to this interface
        for addr in self.addresses:
            lines.append(f"Address = {addr}")

        ## Append listening UDP port if specified
        if self.listen_port is not None:
            lines.append(f"ListenPort = {self.listen_port}")

        ## Append Maximum Transmission Unit if specified
        if self.mtu is not None:
            lines.append(f"MTU = {self.mtu}")

        ## Append DNS servers as comma-separated list
        if self.dns:
            lines.append(f"DNS = {', '.join(self.dns)}")

        ## Append routing table behavior if configured
        if self.table:
            lines.append(f"Table = {self.table}")

        ## Append lifecycle hook scripts
        for cmd in self.pre_up:
            lines.append(f"PreUp = {cmd}")
        for cmd in self.post_up:
            lines.append(f"PostUp = {cmd}")
        for cmd in self.pre_down:
            lines.append(f"PreDown = {cmd}")
        for cmd in self.post_down:
            lines.append(f"PostDown = {cmd}")

        ## Assemble into full section string
        return "\n".join(lines)


@dataclass
class WireGuardConfig:
    """
    Represents an entire WireGuard configuration file (interface + peers).
    """
    ## Local node interface specification
    interface: InterfaceConfig
    ## List of remote peer specifications
    peers: List[PeerConfig] = field(default_factory=list)

    def to_wg_quick(self) -> str:
        """
        Converts this configuration object into standard wg-quick(8) configuration file text.
        """
        ## Start with the primary [Interface] block
        blocks = [self.interface.to_wg_quick_block()]

        ## Append each [Peer] block
        for peer in self.peers:
            blocks.append(peer.to_wg_quick_block())

        ## Join sections with blank lines and ensure trailing newline
        return "\n\n".join(blocks) + "\n"

    def to_systemd_networkd(self, interface_name: str = "wg0") -> Dict[str, str]:
        """
        Generates native systemd-networkd .netdev and .network files.

        Returns:
            Dictionary containing:
            - "{interface_name}.netdev": WireGuard virtual device definition.
            - "{interface_name}.network": IP address assignment and routing rules.
        """
        ## -------------------------------------------------------------------
        ## Construct the .netdev virtual network device definition
        ## -------------------------------------------------------------------
        netdev_lines = [
            "# systemd-networkd virtual network device definition",
            "[NetDev]",
            f"Name={interface_name}",
            "Kind=wireguard",
            "",
            "[WireGuard]",
            f"PrivateKey={self.interface.private_key}",
        ]
        ## Add listening port if specified
        if self.interface.listen_port:
            netdev_lines.append(f"ListenPort={self.interface.listen_port}")

        ## Add each peer section to the netdev file
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

        ## -------------------------------------------------------------------
        ## Construct the .network interface network and IP assignment rules
        ## -------------------------------------------------------------------
        network_lines = [
            "# systemd-networkd interface network and address mapping",
            "[Match]",
            f"Name={interface_name}",
            "",
            "[Network]",
        ]
        ## Bind overlay IP addresses
        for addr in self.interface.addresses:
            network_lines.append(f"Address={addr}")

        ## Configure DNS entries
        if self.interface.dns:
            for dns_ip in self.interface.dns:
                network_lines.append(f"DNS={dns_ip}")

        ## Configure link-level MTU
        if self.interface.mtu:
            network_lines.append("")
            network_lines.append("[Link]")
            network_lines.append(f"MTUBytes={self.interface.mtu}")

        ## Return dictionary mapping filenames to file contents
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
    ## Node alphanumeric hostname or label
    name: str
    ## List of virtual mesh overlay IP addresses
    mesh_ips: List[str]
    ## 44-character Base64 Curve25519 public key
    public_key: str
    ## Optional public socket endpoint (hostname:port or ip:port)
    endpoint: Optional[str] = None
    ## UDP port to bind on local interface
    listen_port: Optional[int] = 51820
    ## Optional local private key (Base64)
    private_key: Optional[str] = None
    ## Optional node-specific preshared key
    preshared_key: Optional[str] = None
    ## Additional subnets (e.g. LAN 192.168.1.0/24) routed to this node
    extra_allowed_ips: List[str] = field(default_factory=list)
    ## Whether this node acts as a central hub relay in hub-and-spoke topologies
    is_hub: bool = False
    ## Optional custom persistent keepalive interval in seconds
    persistent_keepalive: Optional[int] = None
    ## Interface Maximum Transmission Unit (bytes)
    mtu: int = 1420
    ## Custom DNS servers for this node
    dns: List[str] = field(default_factory=list)
    ## Scripting hooks run after interface activation
    post_up: List[str] = field(default_factory=list)
    ## Scripting hooks run after interface teardown
    post_down: List[str] = field(default_factory=list)

    def get_all_routable_ips(self) -> List[str]:
        """
        Returns all IP addresses/subnets routed to this node:
        1. Its overlay mesh IPs stripped to single-host /32 or /128 CIDR masks.
        2. Any extra advertised subnets (LANs).
        """
        ## Accumulator for routable IP CIDR strings
        routable = []

        ## Process each declared mesh overlay IP
        for ip_str in self.mesh_ips:
            try:
                ## Parse string as an IP interface with subnet mask
                interface = ipaddress.ip_interface(ip_str)

                ## In peer configurations, AllowedIPs must route specifically to this host
                ## (e.g. 10.100.0.1/32 or fd00::1/128), NOT the entire subnet /24,
                ## because the entire /24 is shared across all mesh participants.
                if interface.version == 4:
                    routable.append(f"{interface.ip}/32")
                else:
                    routable.append(f"{interface.ip}/128")
            except ValueError:
                ## Fallback to verbatim string if parsing encounters an edge case
                routable.append(ip_str)

        ## Append all extra advertised subnets (e.g. local LAN networks)
        routable.extend(self.extra_allowed_ips)

        ## Return complete list of host and network routes
        return routable


@dataclass
class MeshConfig:
    """
    The top-level declarative blueprint of an entire WireGuard mesh.
    """
    ## Network descriptive name (e.g. 'homelab-mesh')
    network_name: str
    ## Topology model (FULL_MESH or HUB_AND_SPOKE)
    topology: TopologyType = TopologyType.FULL_MESH
    ## Default MTU applied to nodes unless overridden
    default_mtu: int = 1420
    ## Default UDP port applied to nodes unless overridden
    default_port: int = 51820
    ## Collection of participating node specifications
    nodes: List[Node] = field(default_factory=list)
    ## Optional global preshared key applied across all peering relationships
    global_preshared_key: Optional[str] = None

    def get_node(self, name: str) -> Optional[Node]:
        """Looks up a node by name."""
        ## Iterate over all registered nodes and match by name
        for n in self.nodes:
            if n.name == name:
                return n
        ## Return None if node was not found
        return None


@dataclass
class AuditFinding:
    """
    Represents a specific issue discovered during network auditing.
    """
    ## Identifier for the audit rule (e.g. 'COLLISION-001', 'MTU-001')
    rule_id: str
    ## Severity classification (INFO, WARNING, ERROR, CRITICAL)
    severity: AuditSeverity
    ## Short descriptive summary of the finding
    title: str
    ## Detailed explanation of the detected condition
    message: str
    ## Name of the affected node or file path
    node_or_file: str
    ## Concrete remediation instructions to resolve the issue
    recommendation: str

    def to_display_string(self) -> str:
        """Formats the finding with clear visual severity indicators."""
        ## Return standardized multi-line diagnostic report string
        return (
            f"[{self.severity.value}] {self.rule_id}: {self.title}\n"
            f"  Target: {self.node_or_file}\n"
            f"  Detail: {self.message}\n"
            f"  Action: {self.recommendation}"
        )
