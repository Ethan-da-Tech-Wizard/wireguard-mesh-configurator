"""
meshguard.visualizer - ASCII Topology Graphs and WireGuard Routing Matrix Renderer.

This module renders terminal-friendly visual diagrams, routing matrices, and
IP allocation tables for multi-node WireGuard networks.

===============================================================================
THE VALUE OF DETERMINISTIC VISUALIZATION IN OVERLAY NETWORKS:
===============================================================================
In overlay networks (especially mesh and hybrid hub-spoke topologies), mental
models frequently fail to predict actual packet paths:
1. Hub-and-Spoke Relay Ambiguity:
   When Spoke A wishes to ping Spoke B, traffic must traverse the Hub.
   Visualizing the routing matrix instantly exposes whether Spoke A possesses
   the route to Spoke B's /32 host address via the Hub's AllowedIPs.
2. Endpoint Asymmetry:
   If Node A has a public IP and Node B is behind residential CGNAT, traffic
   can only be initiated B -> A unless a keepalive holds the NAT state open.
   The connectivity diagram visually flags NAT boundaries.
"""

from typing import Dict, List, Optional
from meshguard.models import MeshConfig, Node, TopologyType


class MeshVisualizer:
    """
    Renders ASCII graphs, routing matrices, and network status summaries.
    """

    def __init__(self, config: MeshConfig):
        self.config = config

    def render_all(self) -> str:
        """Renders the complete visual diagnostic suite."""
        sections = [
            self.render_header(),
            self.render_node_table(),
            self.render_topology_diagram(),
            self.render_routing_matrix(),
        ]
        return "\n\n".join(sections)

    def render_header(self) -> str:
        """Renders an ASCII header block for the network."""
        top_char = "=" * 70
        title = f" WIREGUARD MESH TOPOLOGY: {self.config.network_name.upper()} "
        topology_desc = f"Topology Model: {self.config.topology.value.upper()} | Total Nodes: {len(self.config.nodes)}"
        return f"{top_char}\n{title.center(70, '=')}\n{topology_desc.center(70)}\n{top_char}"

    def render_node_table(self) -> str:
        """
        Renders a tabular layout of all configured nodes, overlay IPs, and endpoints.
        """
        lines = [
            "NODE INVENTORY & IP ALLOCATION TABLE",
            "─" * 70,
            f"{'Node Name':<16} {'Overlay IP':<18} {'Endpoint':<22} {'Role'}",
            "─" * 70,
        ]

        for node in self.config.nodes:
            ips = ", ".join(node.mesh_ips) if node.mesh_ips else "none"
            ep = node.endpoint or "[NAT / Dynamic]"
            role = "HUB (Relay)" if node.is_hub else "Spoke (Peer)"
            lines.append(f"{node.name:<16} {ips:<18} {ep:<22} {role}")

        lines.append("─" * 70)
        return "\n".join(lines)

    def render_topology_diagram(self) -> str:
        """
        Renders an ASCII graph of node connectivity.
        """
        lines = [
            "CONNECTIVITY DIAGRAM",
            "─" * 70,
        ]

        if self.config.topology == TopologyType.FULL_MESH:
            lines.append("FULL-MESH TOPOLOGY (Decentralized Direct P2P):")
            lines.append("")
            # Render a circular or interconnected mesh representation
            for idx, n in enumerate(self.config.nodes):
                ep_str = f" @ {n.endpoint}" if n.endpoint else " [Behind NAT]"
                ips_str = f" ({', '.join(n.mesh_ips)})"
                lines.append(f"  [{idx + 1}] {n.name}{ips_str}{ep_str}")

            lines.append("")
            lines.append("  Interconnection Graph:")
            node_names = [n.name for n in self.config.nodes]
            for i in range(len(node_names)):
                for j in range(i + 1, len(node_names)):
                    lines.append(f"    {node_names[i]:<14} ◄══════ (Direct P2P Encrypted UDP) ══════► {node_names[j]}")

        elif self.config.topology == TopologyType.HUB_AND_SPOKE:
            lines.append("HUB-AND-SPOKE TOPOLOGY (Centralized Relay):")
            lines.append("")
            hubs = [n for n in self.config.nodes if n.is_hub]
            spokes = [n for n in self.config.nodes if not n.is_hub]
            if not hubs and self.config.nodes:
                hubs = [self.config.nodes[0]]
                spokes = self.config.nodes[1:]

            for hub in hubs:
                lines.append(f"       ╔════════════════════════════════════════════╗")
                lines.append(f"       ║ CENTRAL HUB: {hub.name:<29} ║")
                lines.append(f"       ║ IP: {', '.join(hub.mesh_ips):<38} ║")
                lines.append(f"       ║ Endpoint: {hub.endpoint or 'Dynamic':<32} ║")
                lines.append(f"       ╚════════════════════════════════════════════╝")
                lines.append("                           ││")
                lines.append("        ┌──────────────────┴┴──────────────────┐")
                lines.append("        │                                      │")

                for s_idx, spoke in enumerate(spokes):
                    prefix = "        ├────► " if s_idx < len(spokes) - 1 else "        └────► "
                    ep_info = f"via {spoke.endpoint}" if spoke.endpoint else "[NAT Keepalive 25s]"
                    lines.append(f"{prefix}[Spoke] {spoke.name} ({', '.join(spoke.mesh_ips)}) {ep_info}")

        return "\n".join(lines)

    def render_routing_matrix(self) -> str:
        """
        Generates an N x N routing table matrix indicating how each node reaches every other node.
        """
        lines = [
            "ROUTING PATH MATRIX (Longest-Prefix Cryptokey Mapping)",
            "─" * 70,
        ]

        nodes = self.config.nodes
        col_width = 16
        header = f"{'Source / Dest':<{col_width}}" + "".join(f"{n.name[:12]:<{col_width}}" for n in nodes)
        lines.append(header)
        lines.append("─" * len(header))

        for src in nodes:
            row = [f"{src.name[:12]:<{col_width}}"]
            for dst in nodes:
                if src.name == dst.name:
                    cell = "[SELF]"
                elif self.config.topology == TopologyType.FULL_MESH:
                    cell = "DIRECT P2P"
                elif self.config.topology == TopologyType.HUB_AND_SPOKE:
                    if src.is_hub or dst.is_hub:
                        cell = "DIRECT P2P"
                    else:
                        hubs = [n.name for n in nodes if n.is_hub]
                        hub_name = hubs[0] if hubs else "Hub"
                        cell = f"VIA {hub_name}"
                else:
                    cell = "UNKNOWN"

                row.append(f"{cell:<{col_width}}")
            lines.append("".join(row))

        lines.append("─" * len(header))
        return "\n".join(lines)
