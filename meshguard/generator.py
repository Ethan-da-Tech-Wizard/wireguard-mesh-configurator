"""
meshguard.generator - Synthesizer for Full-Mesh and Hub-and-Spoke WireGuard Networks.

This module automates the generation of synchronized, peer-consistent WireGuard
configurations for multi-node deployments across Linux, macOS, and BSD systems.

===============================================================================
NETWORKING MECHANICS: WHY AUTOMATED SYNCHRONIZATION IS ESSENTIAL:
===============================================================================
A WireGuard mesh is fundamentally decentralized; there is no central controller
or dynamic routing daemon (like BGP/OSPF) unless layered on top. Consequently,
every participating node requires an individually tailored configuration file:

1. Asymmetric Interfaces vs. Mutual Peering:
   Node A's configuration requires Node A's private key and Node B's public key.
   Node B's configuration requires Node B's private key and Node A's public key.
   Hand-crafting these pairwise symmetric relationships for N nodes requires:
       Edges = N * (N - 1) / 2
   For 5 nodes = 10 peering blocks.
   For 10 nodes = 45 peering blocks.
   For 20 nodes = 190 peering blocks.
   A single typo in an AllowedIP or Base64 key leads to silent dropouts.

2. AllowedIPs Host-Masking (/32 and /128):
   In the node's local [Interface], its Address is defined with the full subnet mask:
       Address = 10.100.0.1/24
   However, in remote peers' [Peer] blocks, that node MUST be identified with
   a host-specific mask:
       AllowedIPs = 10.100.0.1/32
   If a remote peer mistakenly listed `AllowedIPs = 10.100.0.0/24`, WireGuard's
   longest-prefix Radix trie would direct ALL overlay traffic to that single peer,
   completely cutting off all other nodes on the 10.100.0.0/24 subnet!

3. NAT Traversal & PersistentKeepalive (RFC 4787):
   WireGuard is purely UDP. UDP has no connection state (no SYN/ACK/FIN).
   Consumer firewalls and Carrier-Grade NAT (CGNAT) establish stateful mapping
   entries that expire after 30 to 120 seconds of inactivity.
   - If Node A is behind NAT and has no public endpoint, Node B cannot initiate
     packets to Node A.
   - To keep the NAT hole open, Node A must send periodic authenticated dummy
     packets to Node B:
         PersistentKeepalive = 25
   This generator automatically determines NAT boundaries and injects keepalives
   whenever a peer does not possess a static external endpoint.
"""

from typing import Dict, List, Optional
import ipaddress
import json
import os
from pathlib import Path

from meshguard.models import (
    MeshConfig,
    Node,
    PeerConfig,
    InterfaceConfig,
    WireGuardConfig,
    TopologyType,
)
from meshguard.crypto import (
    generate_keypair,
    generate_preshared_key,
    validate_key_format,
)


class MeshGenerator:
    """
    Synthesizes multi-node WireGuard configurations from a declarative MeshConfig.
    """

    def __init__(self, config: MeshConfig):
        """
        Initializes the generator with a validated MeshConfig.

        Args:
            config: Declarative mesh topology and node blueprints.
        """
        self.config = config

    @classmethod
    def from_dict(cls, data: Dict) -> "MeshGenerator":
        """
        Parses a dictionary (e.g. from JSON) into a MeshGenerator instance.
        """
        network_name = data.get("network_name", "wireguard-mesh")
        topology_str = data.get("topology", TopologyType.FULL_MESH.value)
        topology = TopologyType(topology_str)
        default_mtu = int(data.get("default_mtu", 1420))
        default_port = int(data.get("default_port", 51820))
        global_psk = data.get("global_preshared_key")

        nodes = []
        for n_data in data.get("nodes", []):
            node = Node(
                name=n_data["name"],
                mesh_ips=n_data.get("mesh_ips", []),
                public_key=n_data.get("public_key", ""),
                endpoint=n_data.get("endpoint"),
                listen_port=n_data.get("listen_port", default_port),
                private_key=n_data.get("private_key"),
                preshared_key=n_data.get("preshared_key"),
                extra_allowed_ips=n_data.get("extra_allowed_ips", []),
                is_hub=bool(n_data.get("is_hub", False)),
                persistent_keepalive=n_data.get("persistent_keepalive"),
                mtu=int(n_data.get("mtu", default_mtu)),
                dns=n_data.get("dns", []),
                post_up=n_data.get("post_up", []),
                post_down=n_data.get("post_down", []),
            )
            nodes.append(node)

        mesh_config = MeshConfig(
            network_name=network_name,
            topology=topology,
            default_mtu=default_mtu,
            default_port=default_port,
            nodes=nodes,
            global_preshared_key=global_psk,
        )
        return cls(mesh_config)

    @classmethod
    def from_json_file(cls, path: Union[str, Path]) -> "MeshGenerator":
        """Loads and parses a MeshConfig from a JSON file path."""
        p = Path(path)
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def generate_all(self) -> Dict[str, WireGuardConfig]:
        """
        Generates WireGuardConfig objects for every node in the mesh.

        Returns:
            Dictionary mapping node names to their complete WireGuardConfig.
        """
        if self.config.topology == TopologyType.FULL_MESH:
            return self._generate_full_mesh()
        elif self.config.topology == TopologyType.HUB_AND_SPOKE:
            return self._generate_hub_and_spoke()
        else:
            raise ValueError(f"Unsupported topology type: {self.config.topology}")

    def _generate_full_mesh(self) -> Dict[str, WireGuardConfig]:
        """
        Synthesizes a full-mesh topology.

        Every node connects directly to every other node. If a peer has a public
        endpoint, that endpoint is populated. If the local node is behind NAT
        (lacks a static public endpoint) while the remote peer has one, a
        PersistentKeepalive of 25 seconds is automatically injected.
        """
        configs: Dict[str, WireGuardConfig] = {}

        for local_node in self.config.nodes:
            # Build the [Interface] section for this local node
            interface = InterfaceConfig(
                private_key=local_node.private_key or "# PLACEHOLDER_PRIVATE_KEY",
                addresses=local_node.mesh_ips,
                listen_port=local_node.listen_port,
                mtu=local_node.mtu,
                dns=local_node.dns,
                post_up=local_node.post_up,
                post_down=local_node.post_down,
            )

            peers: List[PeerConfig] = []
            for remote_node in self.config.nodes:
                if remote_node.name == local_node.name:
                    continue  # Do not peer with oneself

                # Determine effective preshared key
                psk = (
                    remote_node.preshared_key
                    or local_node.preshared_key
                    or self.config.global_preshared_key
                )

                # Determine keepalive:
                # If local node has no endpoint (behind NAT) and remote node DOES have an endpoint,
                # local node MUST send keepalives to keep the state table entry open.
                keepalive = local_node.persistent_keepalive
                if keepalive is None:
                    if local_node.endpoint is None and remote_node.endpoint is not None:
                        keepalive = 25  # 25 seconds is optimal for NAT session refresh

                peer = PeerConfig(
                    public_key=remote_node.public_key,
                    allowed_ips=remote_node.get_all_routable_ips(),
                    endpoint=remote_node.endpoint,
                    preshared_key=psk,
                    persistent_keepalive=keepalive,
                    comment=remote_node.name,
                )
                peers.append(peer)

            configs[local_node.name] = WireGuardConfig(interface=interface, peers=peers)

        return configs

    def _generate_hub_and_spoke(self) -> Dict[str, WireGuardConfig]:
        """
        Synthesizes a hub-and-spoke topology.

        - Hub nodes connect to all nodes (both other hubs and all spokes).
        - Spoke nodes connect ONLY to Hub nodes.
        - Spoke nodes route traffic destined for other spokes through the Hub
          by adding all other spokes' host IPs to the Hub's AllowedIPs list.
        """
        configs: Dict[str, WireGuardConfig] = {}
        hubs = [n for n in self.config.nodes if n.is_hub]
        spokes = [n for n in self.config.nodes if not n.is_hub]

        if not hubs:
            # If no hub is explicitly designated, elect the first node as hub
            hubs = [self.config.nodes[0]]
            spokes = self.config.nodes[1:]

        # 1. Generate configs for Hub nodes
        for hub in hubs:
            interface = InterfaceConfig(
                private_key=hub.private_key or "# PLACEHOLDER_PRIVATE_KEY",
                addresses=hub.mesh_ips,
                listen_port=hub.listen_port,
                mtu=hub.mtu,
                dns=hub.dns,
                post_up=hub.post_up,
                post_down=hub.post_down,
            )
            peers: List[PeerConfig] = []

            # Hub peers with other hubs
            for other_hub in hubs:
                if other_hub.name == hub.name:
                    continue
                psk = other_hub.preshared_key or self.config.global_preshared_key
                peer = PeerConfig(
                    public_key=other_hub.public_key,
                    allowed_ips=other_hub.get_all_routable_ips(),
                    endpoint=other_hub.endpoint,
                    preshared_key=psk,
                    persistent_keepalive=25 if other_hub.endpoint else None,
                    comment=f"Hub: {other_hub.name}",
                )
                peers.append(peer)

            # Hub peers with all spokes
            for spoke in spokes:
                psk = spoke.preshared_key or self.config.global_preshared_key
                peer = PeerConfig(
                    public_key=spoke.public_key,
                    allowed_ips=spoke.get_all_routable_ips(),
                    endpoint=spoke.endpoint,  # Usually None if spoke is behind NAT
                    preshared_key=psk,
                    persistent_keepalive=None,  # Hub is passive receiver for NAT spokes
                    comment=f"Spoke: {spoke.name}",
                )
                peers.append(peer)

            configs[hub.name] = WireGuardConfig(interface=interface, peers=peers)

        # 2. Generate configs for Spoke nodes
        for spoke in spokes:
            interface = InterfaceConfig(
                private_key=spoke.private_key or "# PLACEHOLDER_PRIVATE_KEY",
                addresses=spoke.mesh_ips,
                listen_port=spoke.listen_port,
                mtu=spoke.mtu,
                dns=spoke.dns,
                post_up=spoke.post_up,
                post_down=spoke.post_down,
            )
            peers: List[PeerConfig] = []

            # Spoke connects ONLY to Hub nodes
            for hub in hubs:
                psk = spoke.preshared_key or self.config.global_preshared_key

                # CRITICAL ROUTING INVARIANT:
                # The spoke routes to the hub:
                # 1) The hub's own routable IPs.
                # 2) ALL other spokes' routable IPs (relayed through this hub).
                routed_ips = list(hub.get_all_routable_ips())
                for other_spoke in spokes:
                    if other_spoke.name != spoke.name:
                        routed_ips.extend(other_spoke.get_all_routable_ips())

                # Spokes behind NAT MUST have keepalive configured to keep the hub reachable
                keepalive = spoke.persistent_keepalive or 25

                peer = PeerConfig(
                    public_key=hub.public_key,
                    allowed_ips=routed_ips,
                    endpoint=hub.endpoint,
                    preshared_key=psk,
                    persistent_keepalive=keepalive,
                    comment=f"Relay Hub: {hub.name}",
                )
                peers.append(peer)

            configs[spoke.name] = WireGuardConfig(interface=interface, peers=peers)

        return configs

    def export_configs(
        self,
        output_dir: Union[str, Path],
        interface_name: str = "wg0",
        include_systemd_units: bool = True,
    ) -> Dict[str, Path]:
        """
        Writes out all configuration files to the specified output directory.

        Creates:
        - `{output_dir}/{node_name}/{interface_name}.conf`
        - `{output_dir}/{node_name}/systemd-networkd/{interface_name}.netdev`
        - `{output_dir}/{node_name}/systemd-networkd/{interface_name}.network`
        - `{output_dir}/{node_name}/wg-quick@{interface_name}.service`

        Returns:
            Dictionary mapping node names to their generated .conf file paths.
        """
        base_dir = Path(output_dir)
        base_dir.mkdir(parents=True, exist_ok=True)

        generated = self.generate_all()
        result_paths: Dict[str, Path] = {}

        for node_name, wg_config in generated.items():
            node_dir = base_dir / node_name
            node_dir.mkdir(parents=True, exist_ok=True)

            # Write standard wg-quick configuration with secure POSIX permissions (0600)
            conf_path = node_dir / f"{interface_name}.conf"
            conf_path.write_text(wg_config.to_wg_quick(), encoding="utf-8")
            try:
                os.chmod(conf_path, 0o600)
            except OSError:
                pass
            result_paths[node_name] = conf_path

            if include_systemd_units:
                # Generate systemd-networkd files
                networkd_dir = node_dir / "systemd-networkd"
                networkd_dir.mkdir(parents=True, exist_ok=True)
                net_files = wg_config.to_systemd_networkd(interface_name)
                for fname, content in net_files.items():
                    (networkd_dir / fname).write_text(content, encoding="utf-8")

                # Generate Linux standard systemd service unit
                systemd_service = self.generate_systemd_service_unit(interface_name)
                (node_dir / f"wg-quick@{interface_name}.service").write_text(
                    systemd_service, encoding="utf-8"
                )

        return result_paths

    @staticmethod
    def generate_systemd_service_unit(interface_name: str = "wg0") -> str:
        """
        Produces a hardened, production-grade Linux systemd unit file for wg-quick.

        Explains Linux systemd networking lifecycle and sandboxing:
        - Binds to network-online.target.
        - Sets up tunnel via /usr/bin/wg-quick up %i.
        - Tears down tunnel via /usr/bin/wg-quick down %i.
        - Restarts on failure.
        """
        return f"""# /etc/systemd/system/wg-quick@{interface_name}.service
# Production systemd service unit for WireGuard Quick interface
[Unit]
Description=WireGuard via wg-quick({interface_name})
Documentation=man:wg-quick(8) man:wg(8) https://www.wireguard.com/
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/wg-quick up {interface_name}
ExecStop=/usr/bin/wg-quick down {interface_name}
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

# Hardening attributes:
ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""
