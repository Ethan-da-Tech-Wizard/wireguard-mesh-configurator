"""
Program: WireGuard Mesh Configurator - ASCII Topology Visualizer
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Renders terminal-friendly ASCII diagrams, node inventory tables, connectivity graphs, and routing matrices for multi-node WireGuard networks.
"""

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## Type hinting annotations
from typing import Dict, List, Optional

## ---------------------------------------------------------------------------
## Internal Model Imports
## ---------------------------------------------------------------------------
from meshguard.models import MeshConfig, Node, TopologyType


class MeshVisualizer:
    """
    Renders ASCII graphs, routing matrices, and network status summaries.
    """

    def __init__(self, config: MeshConfig):
        ## Store the mesh blueprint configuration to be rendered
        self.config = config

    def render_all(self) -> str:
        """Renders the complete visual diagnostic suite."""
        ## Compile sections sequentially
        sections = [
            self.render_header(),
            self.render_node_table(),
            self.render_topology_diagram(),
            self.render_routing_matrix(),
        ]
        ## Join sections with double blank lines for terminal readability
        return "\n\n".join(sections)

    def render_header(self) -> str:
        """Renders an ASCII header block for the network."""
        ## Build 70-character banner divider
        top_char = "=" * 70
        title = f" WIREGUARD MESH TOPOLOGY: {self.config.network_name.upper()} "
        topology_desc = f"Topology Model: {self.config.topology.value.upper()} | Total Nodes: {len(self.config.nodes)}"

        ## Center text within the 70-character frame
        return f"{top_char}\n{title.center(70, '=')}\n{topology_desc.center(70)}\n{top_char}"

    def render_node_table(self) -> str:
        """
        Renders a tabular layout of all configured nodes, overlay IPs, and endpoints.
        """
        ## Initialize table header lines
        lines = [
            "NODE INVENTORY & IP ALLOCATION TABLE",
            "─" * 70,
            f"{'Node Name':<16} {'Overlay IP':<18} {'Endpoint':<22} {'Role'}",
            "─" * 70,
        ]

        ## Populate rows for each participating node
        for node in self.config.nodes:
            ips = ", ".join(node.mesh_ips) if node.mesh_ips else "none"
            ep = node.endpoint or "[NAT / Dynamic]"
            role = "HUB (Relay)" if node.is_hub else "Spoke (Peer)"
            lines.append(f"{node.name:<16} {ips:<18} {ep:<22} {role}")

        ## Append bottom table border
        lines.append("─" * 70)
        return "\n".join(lines)

    def render_topology_diagram(self) -> str:
        """
        Renders an ASCII graph of node connectivity.
        """
        ## Initialize diagram header
        lines = [
            "CONNECTIVITY DIAGRAM",
            "─" * 70,
        ]

        ## -------------------------------------------------------------------
        ## Case 1: Full-Mesh Topology Rendering
        ## -------------------------------------------------------------------
        if self.config.topology == TopologyType.FULL_MESH:
            lines.append("FULL-MESH TOPOLOGY (Decentralized Direct P2P):")
            lines.append("")

            ## Render individual node cards
            for idx, n in enumerate(self.config.nodes):
                ep_str = f" @ {n.endpoint}" if n.endpoint else " [Behind NAT]"
                ips_str = f" ({', '.join(n.mesh_ips)})"
                lines.append(f"  [{idx + 1}] {n.name}{ips_str}{ep_str}")

            lines.append("")
            lines.append("  Interconnection Graph:")
            node_names = [n.name for n in self.config.nodes]

            ## Generate pairwise mesh link arrows: N * (N - 1) / 2 links
            for i in range(len(node_names)):
                for j in range(i + 1, len(node_names)):
                    lines.append(f"    {node_names[i]:<14} ◄══════ (Direct P2P Encrypted UDP) ══════► {node_names[j]}")

        ## -------------------------------------------------------------------
        ## Case 2: Hub-and-Spoke Topology Rendering
        ## -------------------------------------------------------------------
        elif self.config.topology == TopologyType.HUB_AND_SPOKE:
            lines.append("HUB-AND-SPOKE TOPOLOGY (Centralized Relay):")
            lines.append("")

            ## Partition hubs and spokes
            hubs = [n for n in self.config.nodes if n.is_hub]
            spokes = [n for n in self.config.nodes if not n.is_hub]

            ## Elect first node if no hub explicitly tagged
            if not hubs and self.config.nodes:
                hubs = [self.config.nodes[0]]
                spokes = self.config.nodes[1:]

            ## Draw each central relay hub box
            for hub in hubs:
                lines.append("       ╔════════════════════════════════════════════╗")
                lines.append(f"       ║ CENTRAL HUB: {hub.name:<29} ║")
                lines.append(f"       ║ IP: {', '.join(hub.mesh_ips):<38} ║")
                lines.append(f"       ║ Endpoint: {hub.endpoint or 'Dynamic':<32} ║")
                lines.append("       ╚════════════════════════════════════════════╝")
                lines.append("                           ││")
                lines.append("        ┌──────────────────┴┴──────────────────┐")
                lines.append("        │                                      │")

                ## Draw spoke connection branches
                for s_idx, spoke in enumerate(spokes):
                    prefix = "        ├────► " if s_idx < len(spokes) - 1 else "        └────► "
                    ep_info = f"via {spoke.endpoint}" if spoke.endpoint else "[NAT Keepalive 25s]"
                    lines.append(f"{prefix}[Spoke] {spoke.name} ({', '.join(spoke.mesh_ips)}) {ep_info}")

        ## Return joined diagram lines
        return "\n".join(lines)

    def render_routing_matrix(self) -> str:
        """
        Generates an N x N routing table matrix indicating how each node reaches every other node.
        """
        ## Initialize routing matrix header
        lines = [
            "ROUTING PATH MATRIX (Longest-Prefix Cryptokey Mapping)",
            "─" * 70,
        ]

        nodes = self.config.nodes
        col_width = 16

        ## Build table column headers
        header = f"{'Source / Dest':<{col_width}}" + "".join(f"{n.name[:12]:<{col_width}}" for n in nodes)
        lines.append(header)
        lines.append("─" * len(header))

        ## Build each row showing source -> destination routing path
        for src in nodes:
            row = [f"{src.name[:12]:<{col_width}}"]
            for dst in nodes:
                ## Self-referential loopback
                if src.name == dst.name:
                    cell = "[SELF]"
                ## Full-mesh direct tunnel
                elif self.config.topology == TopologyType.FULL_MESH:
                    cell = "DIRECT P2P"
                ## Hub-and-spoke routed tunnel
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

        ## Append bottom matrix border
        lines.append("─" * len(header))
        return "\n".join(lines)
