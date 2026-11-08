"""
meshguard.auditor - Subnet Collision Detector, MTU Verifier, and WireGuard Syntax Auditor.

This module inspects WireGuard configuration files (.conf) and mesh blueprints
to detect protocol violations, routing collisions, and operational hazards.

===============================================================================
THE FIVE DEADLY SINS OF WIREGUARD DEPLOYMENT:
===============================================================================
1. Overlapping AllowedIPs on the Same Interface:
   WireGuard does NOT load-balance between peers with overlapping AllowedIPs.
   WireGuard uses an internal Radix trie (longest-prefix match).
   If Peer A has 10.0.0.0/24 and Peer B has 10.0.0.5/32:
   - Outbound traffic to 10.0.0.5 will route to Peer B.
   - Inbound traffic from 10.0.0.5 encrypted by Peer A will be SILENTLY DROPPED
     by the kernel because of cryptokey anti-spoofing lookup mismatch!
   - If two peers specify the EXACT same subnet (e.g. both claim 10.0.0.2/32),
     only ONE peer will receive the route in the kernel; the other is permanently
     orphaned without an error code from `wg`.

2. MTU Misconfiguration & Path MTU (PMTU) Blackholes:
   Standard Ethernet frames are 1500 bytes.
   WireGuard encapsulates IP packets inside UDP datagrams.
   Overhead breakdown:
     - Outer IP header: 20 bytes (IPv4) or 40 bytes (IPv6)
     - UDP header: 8 bytes
     - WireGuard encapsulation header: 32 bytes (Type, Receiver, Counter, Poly1305 MAC)
     Total WireGuard overhead = 60 bytes (IPv4) or 80 bytes (IPv6).
   If MTU is set to 1500:
   - Encapsulated UDP packets become 1560 or 1580 bytes.
   - Routers on the internet must fragment the packet.
   - Many firewalls drop UDP fragments (security evasion prevention).
   - If DF (Don't Fragment) is set and intermediate routers drop ICMP Type 3 Code 4
     ("Destination Unreachable: Fragmentation Needed"), connections hang during
     TLS handshakes or large HTTP transfers. This is a classic PMTU blackhole!
   - Recommended MTU: 1420 (accommodates 1500 - 80 = 1420 bytes for IPv6 + PPPoE).
   - Absolute Minimum MTU: 1280 (RFC 8200 mandates IPv6 MTU >= 1280).

3. Insecure File Permissions:
   WireGuard configuration files contain unencrypted private keys. If a .conf file
   has permissions 0644 (world-readable), any local unprivileged process can
   steal the identity and impersonate the node.

4. NAT Expiry Without PersistentKeepalive:
   WireGuard is silent when idle. Stateful NAT firewalls purge UDP mappings after
   30 to 120 seconds. Without `PersistentKeepalive = 25`, inbound sessions fail.

5. Key Format Violations:
   Invalid Base64 length, incorrect padding, or invalid byte length cause `wg`
   and `wg-quick` to abort parsing.
"""

import ipaddress
import os
from pathlib import Path
import re
import stat
from typing import Dict, List, Optional, Set, Tuple, Union

from meshguard.models import (
    AuditFinding,
    AuditSeverity,
    InterfaceConfig,
    MeshConfig,
    PeerConfig,
    WireGuardConfig,
)
from meshguard.crypto import (
    validate_key_format,
    derive_public_key,
)


class MeshAuditor:
    """
    Diagnostic analysis engine for WireGuard configurations and meshes.
    """

    def __init__(self):
        self.findings: List[AuditFinding] = []

    def audit_mesh_config(self, mesh: MeshConfig) -> List[AuditFinding]:
        """
        Audits an entire high-level MeshConfig blueprint.

        Checks:
        1. Duplicate node names.
        2. Duplicate assigned overlay IP addresses.
        3. Curve25519 keypair validity and consistency.
        4. Subnet collisions between node extra_allowed_ips and mesh subnets.
        5. MTU boundaries.
        6. NAT keepalive prerequisites.
        """
        self.findings.clear()

        seen_names: Set[str] = set()
        seen_ips: Dict[str, str] = {}  # ip -> node_name
        all_networks: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []

        for node in mesh.nodes:
            # 1. Unique Node Names
            if node.name in seen_names:
                self.findings.append(
                    AuditFinding(
                        rule_id="NODE-001",
                        severity=AuditSeverity.CRITICAL,
                        title="Duplicate Node Name",
                        message=f"Node name '{node.name}' is defined multiple times in the mesh blueprint.",
                        node_or_file=node.name,
                        recommendation="Ensure all node names in the mesh specification are unique.",
                    )
                )
            seen_names.add(node.name)

            # 2. Key Validation
            if node.public_key:
                valid, msg = validate_key_format(node.public_key)
                if not valid:
                    self.findings.append(
                        AuditFinding(
                            rule_id="KEY-001",
                            severity=AuditSeverity.ERROR,
                            title="Invalid Public Key Format",
                            message=f"Node '{node.name}' public key is invalid: {msg}",
                            node_or_file=node.name,
                            recommendation="Provide a valid 32-byte Base64-encoded Curve25519 public key.",
                        )
                    )

            if node.private_key:
                valid, msg = validate_key_format(node.private_key)
                if not valid:
                    self.findings.append(
                        AuditFinding(
                            rule_id="KEY-002",
                            severity=AuditSeverity.ERROR,
                            title="Invalid Private Key Format",
                            message=f"Node '{node.name}' private key is invalid: {msg}",
                            node_or_file=node.name,
                            recommendation="Provide a valid 32-byte Base64-encoded Curve25519 private key.",
                        )
                    )
                else:
                    # Check if derived public key matches declared public key
                    try:
                        derived_pub = derive_public_key(node.private_key)
                        if node.public_key and derived_pub != node.public_key:
                            self.findings.append(
                                AuditFinding(
                                    rule_id="KEY-003",
                                    severity=AuditSeverity.CRITICAL,
                                    title="Public/Private Key Mismatch",
                                    message=(
                                        f"Node '{node.name}' public key does not correspond to its private key! "
                                        f"Expected {derived_pub}, got {node.public_key}."
                                    ),
                                    node_or_file=node.name,
                                    recommendation="Derive the public key from the private key or align the pair.",
                                )
                            )
                    except Exception as e:
                        self.findings.append(
                            AuditFinding(
                                rule_id="KEY-004",
                                severity=AuditSeverity.ERROR,
                                title="Public Key Derivation Failed",
                                message=f"Failed to derive public key for node '{node.name}': {e}",
                                node_or_file=node.name,
                                recommendation="Check private key bytes and base64 formatting.",
                            )
                        )

            # 3. IP Assignment and Collision Checks
            for ip_str in node.mesh_ips:
                try:
                    iface = ipaddress.ip_interface(ip_str)
                    host_ip_str = str(iface.ip)
                    if host_ip_str in seen_ips:
                        self.findings.append(
                            AuditFinding(
                                rule_id="IP-001",
                                severity=AuditSeverity.CRITICAL,
                                title="Duplicate IP Address Allocation",
                                message=(
                                    f"IP address '{host_ip_str}' is assigned to both "
                                    f"'{seen_ips[host_ip_str]}' and '{node.name}'."
                                ),
                                node_or_file=node.name,
                                recommendation="Assign a unique IP address to each node interface.",
                            )
                        )
                    else:
                        seen_ips[host_ip_str] = node.name

                    # Record host network (/32 or /128)
                    host_net = ipaddress.ip_network(
                        f"{iface.ip}/{32 if iface.version == 4 else 128}"
                    )
                    all_networks.append((host_net, node.name))
                except ValueError as err:
                    self.findings.append(
                        AuditFinding(
                            rule_id="IP-002",
                            severity=AuditSeverity.ERROR,
                            title="Malformed IP Address Specification",
                            message=f"Node '{node.name}' has invalid IP address '{ip_str}': {err}",
                            node_or_file=node.name,
                            recommendation="Specify IP addresses in standard CIDR notation (e.g. 10.100.0.1/24).",
                        )
                    )

            # 4. Extra Advertised Subnets Collision Check
            for extra in node.extra_allowed_ips:
                try:
                    extra_net = ipaddress.ip_network(extra, strict=False)
                    # Check for overlap with already registered networks
                    for existing_net, owner_node in all_networks:
                        if extra_net.overlaps(existing_net) and owner_node != node.name:
                            self.findings.append(
                                AuditFinding(
                                    rule_id="IP-003",
                                    severity=AuditSeverity.CRITICAL,
                                    title="Subnet Collision in AllowedIPs",
                                    message=(
                                        f"Node '{node.name}' advertises '{extra_net}' which overlaps with "
                                        f"network '{existing_net}' registered to '{owner_node}'."
                                    ),
                                    node_or_file=node.name,
                                    recommendation="Resolve overlapping subnets; WireGuard cryptokey routing requires disjoint destination IPs.",
                                )
                            )
                    all_networks.append((extra_net, node.name))
                except ValueError as err:
                    self.findings.append(
                        AuditFinding(
                            rule_id="IP-004",
                            severity=AuditSeverity.ERROR,
                            title="Malformed Extra Subnet",
                            message=f"Node '{node.name}' extra subnet '{extra}' is invalid: {err}",
                            node_or_file=node.name,
                            recommendation="Check CIDR notation for advertised subnets.",
                        )
                    )

            # 5. MTU Verification
            self._audit_mtu(node.mtu, target_name=node.name)

            # 6. Endpoint & NAT Keepalive Verification
            if node.endpoint:
                self._audit_endpoint(node.endpoint, target_name=node.name)
            else:
                # Behind NAT: check if keepalive is explicitly configured or will default
                if node.persistent_keepalive is not None and node.persistent_keepalive > 30:
                    self.findings.append(
                        AuditFinding(
                            rule_id="NAT-001",
                            severity=AuditSeverity.WARNING,
                            title="PersistentKeepalive Exceeds Safe NAT Interval",
                            message=(
                                f"Node '{node.name}' has keepalive set to {node.persistent_keepalive}s. "
                                "Many stateful firewalls drop UDP mappings after 30 seconds."
                            ),
                            node_or_file=node.name,
                            recommendation="Set PersistentKeepalive to 25 seconds for reliable NAT hole-punching.",
                        )
                    )

        return self.findings

    def audit_wireguard_config(
        self, config: WireGuardConfig, file_path: Optional[Union[str, Path]] = None
    ) -> List[AuditFinding]:
        """
        Audits an individual parsed WireGuard configuration (e.g. from wg0.conf).

        Checks:
        1. Interface private key validity.
        2. Interface MTU sizing.
        3. AllowedIPs collisions across peers on this interface.
        4. Valid endpoints and ports.
        5. File system permission safety (if file_path provided).
        """
        target = str(file_path) if file_path else "WireGuardConfig"

        # 1. Interface Private Key
        if config.interface.private_key:
            valid, msg = validate_key_format(config.interface.private_key)
            if not valid:
                self.findings.append(
                    AuditFinding(
                        rule_id="KEY-002",
                        severity=AuditSeverity.ERROR,
                        title="Invalid Interface PrivateKey",
                        message=f"Interface private key is invalid: {msg}",
                        node_or_file=target,
                        recommendation="Set a valid 32-byte Base64-encoded private key.",
                    )
                )

        # 2. MTU Verification
        if config.interface.mtu:
            self._audit_mtu(config.interface.mtu, target_name=target)

        # 3. File Permissions (POSIX security)
        if file_path:
            self._audit_file_permissions(Path(file_path))

        # 4. Peer AllowedIPs Overlap Analysis (Radix Trie Conflict Detection)
        registered_peer_nets: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []

        for idx, peer in enumerate(config.peers):
            peer_label = peer.comment or f"Peer #{idx + 1} ({peer.public_key[:8]}...)"

            # Validate peer public key
            valid, msg = validate_key_format(peer.public_key)
            if not valid:
                self.findings.append(
                    AuditFinding(
                        rule_id="KEY-001",
                        severity=AuditSeverity.ERROR,
                        title="Invalid Peer PublicKey",
                        message=f"Peer '{peer_label}' has invalid public key: {msg}",
                        node_or_file=target,
                        recommendation="Verify the peer's public key string.",
                    )
                )

            # Check peer endpoint
            if peer.endpoint:
                self._audit_endpoint(peer.endpoint, target_name=f"{target} -> {peer_label}")

            # Check peer AllowedIPs
            for allowed_str in peer.allowed_ips:
                try:
                    current_net = ipaddress.ip_network(allowed_str, strict=False)

                    # Look for overlap with already registered peers on this interface
                    for prev_net, prev_peer in registered_peer_nets:
                        if current_net.overlaps(prev_net):
                            self.findings.append(
                                AuditFinding(
                                    rule_id="COLLISION-001",
                                    severity=AuditSeverity.CRITICAL,
                                    title="Peer AllowedIPs Overlap Collision",
                                    message=(
                                        f"AllowedIPs collision detected on interface! Peer '{peer_label}' "
                                        f"claims '{current_net}' which overlaps with '{prev_net}' "
                                        f"claimed by '{prev_peer}'. WireGuard cryptokey routing cannot "
                                        "disambiguate this route and will silently drop or hijack packets."
                                    ),
                                    node_or_file=target,
                                    recommendation="Ensure AllowedIPs entries across peers on the same interface are mutually exclusive.",
                                )
                            )

                    registered_peer_nets.append((current_net, peer_label))
                except ValueError as err:
                    self.findings.append(
                        AuditFinding(
                            rule_id="IP-005",
                            severity=AuditSeverity.ERROR,
                            title="Invalid AllowedIPs CIDR",
                            message=f"Peer '{peer_label}' has invalid AllowedIPs entry '{allowed_str}': {err}",
                            node_or_file=target,
                            recommendation="AllowedIPs must be valid IPv4 or IPv6 CIDR notations.",
                        )
                    )

        return self.findings

    def audit_directory(self, dir_path: Union[str, Path]) -> List[AuditFinding]:
        """
        Scans a directory for all .conf files and audits them individually and collectively.
        """
        p = Path(dir_path)
        if not p.is_dir():
            raise NotADirectoryError(f"Directory not found: {dir_path}")

        conf_files = list(p.rglob("*.conf"))
        if not conf_files:
            self.findings.append(
                AuditFinding(
                    rule_id="DIR-001",
                    severity=AuditSeverity.WARNING,
                    title="No WireGuard Configs Found",
                    message=f"No *.conf files found in directory {dir_path}",
                    node_or_file=str(dir_path),
                    recommendation="Verify path or generate configurations first.",
                )
            )
            return self.findings

        for cf in conf_files:
            try:
                wg_conf = self.parse_wg_conf_file(cf)
                self.audit_wireguard_config(wg_conf, file_path=cf)
            except Exception as e:
                self.findings.append(
                    AuditFinding(
                        rule_id="PARSE-001",
                        severity=AuditSeverity.ERROR,
                        title="Failed to Parse WireGuard Config",
                        message=f"Could not parse '{cf.name}': {e}",
                        node_or_file=str(cf),
                        recommendation="Check file syntax against wg-quick(8) format.",
                    )
                )

        return self.findings

    def _audit_mtu(self, mtu: int, target_name: str):
        """Verifies MTU sizing against physical and protocol constraints."""
        if mtu < 1280:
            self.findings.append(
                AuditFinding(
                    rule_id="MTU-001",
                    severity=AuditSeverity.ERROR,
                    title="MTU Violates RFC 8200 IPv6 Minimum",
                    message=(
                        f"MTU of {mtu} bytes is below the mandatory IPv6 minimum of 1280 bytes. "
                        "All IPv6 traffic will be broken over this interface."
                    ),
                    node_or_file=target_name,
                    recommendation="Increase MTU to at least 1280 (recommended: 1420).",
                )
            )
        elif mtu == 1500:
            self.findings.append(
                AuditFinding(
                    rule_id="MTU-002",
                    severity=AuditSeverity.WARNING,
                    title="MTU Set to Standard Ethernet 1500 (High Fragmentation Risk)",
                    message=(
                        f"MTU of 1500 bytes does not account for WireGuard UDP encapsulation overhead "
                        "(60-80 bytes). This will cause IP packet fragmentation or Path MTU blackholes "
                        "if upstream intermediate networks drop ICMP Packet Too Big messages."
                    ),
                    node_or_file=target_name,
                    recommendation="Reduce MTU to 1420 (or 1440 for pure IPv4) to eliminate encapsulation fragmentation.",
                )
            )
        elif mtu > 1500:
            self.findings.append(
                AuditFinding(
                    rule_id="MTU-003",
                    severity=AuditSeverity.WARNING,
                    title="Jumbo Frame MTU (> 1500 bytes)",
                    message=(
                        f"MTU of {mtu} bytes requires Jumbo Frame support (MTU >= 9000) on all intermediate "
                        "underlay switches and routers. This will fail across the public internet."
                    ),
                    node_or_file=target_name,
                    recommendation="Ensure the entire physical underlay path supports jumbo frames, or use MTU 1420.",
                )
            )

    def _audit_endpoint(self, endpoint: str, target_name: str):
        """Validates that endpoint is a valid host:port string."""
        # Split host and port
        if ":" not in endpoint:
            self.findings.append(
                AuditFinding(
                    rule_id="EP-001",
                    severity=AuditSeverity.ERROR,
                    title="Endpoint Missing Port",
                    message=f"Endpoint '{endpoint}' does not specify a UDP port.",
                    node_or_file=target_name,
                    recommendation="Specify endpoint as <host>:<port> or [<ipv6>]:<port>.",
                )
            )
            return

        # Check IPv6 bracketed endpoint e.g. [2001:db8::1]:51820
        if endpoint.startswith("["):
            match = re.match(r"^\[([a-fA-F0-9:]+)\]:(\d+)$", endpoint)
            if not match:
                self.findings.append(
                    AuditFinding(
                        rule_id="EP-002",
                        severity=AuditSeverity.ERROR,
                        title="Malformed IPv6 Endpoint",
                        message=f"IPv6 Endpoint '{endpoint}' is not in [<ipv6>]:<port> format.",
                        node_or_file=target_name,
                        recommendation="Format as [2001:db8::1]:51820.",
                    )
                )
                return
            port = int(match.group(2))
        else:
            parts = endpoint.rsplit(":", 1)
            try:
                port = int(parts[1])
            except ValueError:
                self.findings.append(
                    AuditFinding(
                        rule_id="EP-003",
                        severity=AuditSeverity.ERROR,
                        title="Invalid Endpoint Port Number",
                        message=f"Port in endpoint '{endpoint}' is not a valid integer.",
                        node_or_file=target_name,
                        recommendation="Use an integer port between 1 and 65535.",
                    )
                )
                return

        if not (1 <= port <= 65535):
            self.findings.append(
                AuditFinding(
                    rule_id="EP-004",
                    severity=AuditSeverity.ERROR,
                    title="Endpoint Port Out of Range",
                    message=f"Endpoint port {port} is out of valid range (1-65535).",
                    node_or_file=target_name,
                    recommendation="Set UDP port between 1 and 65535 (default 51820).",
                )
            )

    def _audit_file_permissions(self, path: Path):
        """Checks POSIX file permissions for configuration containing private keys."""
        if not path.exists():
            return
        try:
            mode = path.stat().st_mode
            # Check if group or others have read or write permissions
            if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
                perm_octal = oct(stat.S_IMODE(mode))
                self.findings.append(
                    AuditFinding(
                        rule_id="SEC-001",
                        severity=AuditSeverity.CRITICAL,
                        title="Insecure File Permissions on WireGuard Config",
                        message=(
                            f"File '{path.name}' has permissions {perm_octal}, allowing group or world read access. "
                            "WireGuard configurations contain unencrypted private keys!"
                        ),
                        node_or_file=str(path),
                        recommendation=f"Run: chmod 600 {path}",
                    )
                )
        except OSError:
            pass

    @staticmethod
    def parse_wg_conf_file(path: Union[str, Path]) -> WireGuardConfig:
        """Reads and parses a wg-quick format file from disk."""
        p = Path(path)
        content = p.read_text(encoding="utf-8")
        return MeshAuditor.parse_wg_conf(content)

    @staticmethod
    def parse_wg_conf(content: str) -> WireGuardConfig:
        """
        Pure-Python parser for wg-quick configuration files.

        Parses [Interface] and multiple [Peer] sections, handling comments,
        comma-separated addresses, and multi-value options.
        """
        current_section: Optional[str] = None
        interface_params: Dict[str, Any] = {
            "private_key": "",
            "addresses": [],
            "listen_port": None,
            "mtu": 1420,
            "dns": [],
            "pre_up": [],
            "post_up": [],
            "pre_down": [],
            "post_down": [],
            "table": None,
        }
        peers: List[PeerConfig] = []
        current_peer_params: Optional[Dict[str, Any]] = None
        current_comment: Optional[str] = None

        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Handle comments
            if not line:
                continue
            if line.startswith("#") or line.startswith(";"):
                # Check for node annotation comments like "# Node: my-server"
                if "node:" in line.lower():
                    current_comment = line.split(":", 1)[1].strip()
                continue

            # Section header
            if line.startswith("[") and line.endswith("]"):
                header = line[1:-1].strip().lower()
                if header == "interface":
                    current_section = "interface"
                elif header == "peer":
                    if current_peer_params is not None:
                        peers.append(MeshAuditor._build_peer(current_peer_params))
                    current_peer_params = {
                        "public_key": "",
                        "allowed_ips": [],
                        "endpoint": None,
                        "preshared_key": None,
                        "persistent_keepalive": None,
                        "comment": current_comment,
                    }
                    current_comment = None
                    current_section = "peer"
                else:
                    current_section = None
                continue

            # Key = Value lines
            if "=" in line:
                key, val = [p.strip() for p in line.split("=", 1)]
                key_lower = key.lower()

                if current_section == "interface":
                    if key_lower == "privatekey":
                        interface_params["private_key"] = val
                    elif key_lower == "address":
                        # Can be comma-separated list of addresses
                        for addr in val.split(","):
                            interface_params["addresses"].append(addr.strip())
                    elif key_lower == "listenport":
                        interface_params["listen_port"] = int(val)
                    elif key_lower == "mtu":
                        interface_params["mtu"] = int(val)
                    elif key_lower == "dns":
                        for d in val.split(","):
                            interface_params["dns"].append(d.strip())
                    elif key_lower == "preup":
                        interface_params["pre_up"].append(val)
                    elif key_lower == "postup":
                        interface_params["post_up"].append(val)
                    elif key_lower == "predown":
                        interface_params["pre_down"].append(val)
                    elif key_lower == "postdown":
                        interface_params["post_down"].append(val)
                    elif key_lower == "table":
                        interface_params["table"] = val

                elif current_section == "peer" and current_peer_params is not None:
                    if key_lower == "publickey":
                        current_peer_params["public_key"] = val
                    elif key_lower == "allowedips":
                        for a in val.split(","):
                            current_peer_params["allowed_ips"].append(a.strip())
                    elif key_lower == "endpoint":
                        current_peer_params["endpoint"] = val
                    elif key_lower == "presharedkey":
                        current_peer_params["preshared_key"] = val
                    elif key_lower == "persistentkeepalive":
                        current_peer_params["persistent_keepalive"] = int(val)

        # Flush final peer
        if current_peer_params is not None:
            peers.append(MeshAuditor._build_peer(current_peer_params))

        interface = InterfaceConfig(**interface_params)
        return WireGuardConfig(interface=interface, peers=peers)

    @staticmethod
    def _build_peer(params: Dict[str, Any]) -> PeerConfig:
        return PeerConfig(
            public_key=params["public_key"],
            allowed_ips=params["allowed_ips"],
            endpoint=params["endpoint"],
            preshared_key=params["preshared_key"],
            persistent_keepalive=params["persistent_keepalive"],
            comment=params.get("comment"),
        )
