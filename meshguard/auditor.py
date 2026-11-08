"""
Program: WireGuard Mesh Configurator - Subnet Collision Detector & Auditor
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Audits WireGuard mesh configurations and .conf files for Cryptokey routing collisions, MTU misconfigurations, weak or mismatched Curve25519 keys, and insecure file permissions.
"""

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## IP network manipulation module for CIDR calculation and overlap detection
import ipaddress
## Operating system interface for filesystem stats and permissions
import os
## Object-oriented filesystem path manipulation
from pathlib import Path
## Regular expression engine for parsing endpoints and tokens
import re
## File mode permission bit constants
import stat
## Type hinting annotations
from typing import Dict, List, Optional, Set, Tuple, Union, Any

## ---------------------------------------------------------------------------
## Internal Model & Cryptographic Imports
## ---------------------------------------------------------------------------
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
        ## Accumulator list for diagnostic findings discovered during an audit run
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
        ## Clear findings list from any previous audit run
        self.findings.clear()

        ## Tracking set to detect duplicate node names across the blueprint
        seen_names: Set[str] = set()

        ## Tracking dictionary mapping IP string to node name for duplicate IP detection
        seen_ips: Dict[str, str] = {}

        ## Master list of all registered networks and their owning nodes for collision detection
        all_networks: List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], str]] = []

        ## Iterate through each node in the mesh configuration
        for node in mesh.nodes:
            ## ---------------------------------------------------------------
            ## 1. Unique Node Names Check
            ## ---------------------------------------------------------------
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

            ## ---------------------------------------------------------------
            ## 2. Cryptographic Keypair Validation
            ## ---------------------------------------------------------------
            ## Verify public key format if present
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

            ## Verify private key format and mathematical alignment with public key
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
                    ## Check if derived public key matches declared public key
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

            ## ---------------------------------------------------------------
            ## 3. IP Assignment and Collision Checks
            ## ---------------------------------------------------------------
            for ip_str in node.mesh_ips:
                try:
                    ## Parse IP interface string
                    iface = ipaddress.ip_interface(ip_str)
                    host_ip_str = str(iface.ip)

                    ## Check for duplicate IP allocation
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

                    ## Record host network (/32 or /128) in master routing list
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

            ## ---------------------------------------------------------------
            ## 4. Extra Advertised Subnets Collision Check
            ## ---------------------------------------------------------------
            for extra in node.extra_allowed_ips:
                try:
                    extra_net = ipaddress.ip_network(extra, strict=False)

                    ## Check for overlap with already registered networks
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

            ## ---------------------------------------------------------------
            ## 5. MTU Verification
            ## ---------------------------------------------------------------
            self._audit_mtu(node.mtu, target_name=node.name)

            ## ---------------------------------------------------------------
            ## 6. Endpoint & NAT Keepalive Verification
            ## ---------------------------------------------------------------
            if node.endpoint:
                self._audit_endpoint(node.endpoint, target_name=node.name)
            else:
                ## Behind NAT: check if keepalive is explicitly configured or will default
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

        ## Return accumulated findings list
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
        ## Target label for diagnostic reporting
        target = str(file_path) if file_path else "WireGuardConfig"

        ## -------------------------------------------------------------------
        ## 1. Interface Private Key Audit
        ## -------------------------------------------------------------------
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

        ## -------------------------------------------------------------------
        ## 2. Interface MTU Verification
        ## -------------------------------------------------------------------
        if config.interface.mtu:
            self._audit_mtu(config.interface.mtu, target_name=target)

        ## -------------------------------------------------------------------
        ## 3. File Permissions Audit (POSIX security)
        ## -------------------------------------------------------------------
        if file_path:
            self._audit_file_permissions(Path(file_path))

        ## -------------------------------------------------------------------
        ## 4. Peer AllowedIPs Overlap Analysis (Radix Trie Conflict Detection)
        ## -------------------------------------------------------------------
        registered_peer_nets: List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], str]] = []

        ## Loop through each configured remote peer
        for idx, peer in enumerate(config.peers):
            peer_label = peer.comment or f"Peer #{idx + 1} ({peer.public_key[:8]}...)"

            ## Validate peer public key format
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

            ## Check peer endpoint socket syntax
            if peer.endpoint:
                self._audit_endpoint(peer.endpoint, target_name=f"{target} -> {peer_label}")

            ## Check peer AllowedIPs for overlaps on this local interface
            for allowed_str in peer.allowed_ips:
                try:
                    current_net = ipaddress.ip_network(allowed_str, strict=False)

                    ## Look for overlap with already registered peers on this interface
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

                    ## Record this peer's network route
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

        ## Return list of findings for this configuration
        return self.findings

    def audit_directory(self, dir_path: Union[str, Path]) -> List[AuditFinding]:
        """
        Scans a directory for all .conf files and audits them individually and collectively.
        """
        ## Ensure input path is a Path object
        p = Path(dir_path)
        if not p.is_dir():
            raise NotADirectoryError(f"Directory not found: {dir_path}")

        ## Recursively locate all WireGuard configuration files (.conf)
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

        ## Audit each discovered configuration file
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

        ## Return accumulated findings list
        return self.findings

    def _audit_mtu(self, mtu: int, target_name: str):
        """Verifies MTU sizing against physical and protocol constraints."""
        ## IPv6 mandates a minimum link MTU of 1280 bytes (RFC 8200)
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
        ## MTU of 1500 doesn't leave room for WireGuard UDP encapsulation overhead
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
        ## Jumbo frame MTU (> 1500 bytes) requires explicit underlay support
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
        ## Endpoint must contain a colon separating host and UDP port
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

        ## Check IPv6 bracketed endpoint e.g. [2001:db8::1]:51820
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
            ## Parse IPv4 or hostname endpoint
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

        ## Port must be within valid 16-bit UDP port range
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
            ## Check if group or others have read or write permissions
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
            pass  ## Non-POSIX systems

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
        ## Current active configuration section header ('interface' or 'peer')
        current_section: Optional[str] = None

        ## Dictionary accumulating parameters for the [Interface] section
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

        ## List of PeerConfig objects created while parsing [Peer] sections
        peers: List[PeerConfig] = []

        ## Dictionary accumulating parameters for the active [Peer] section
        current_peer_params: Optional[Dict[str, Any]] = None

        ## Holds any comment immediately preceding a section (e.g. node name comment)
        current_comment: Optional[str] = None

        ## Process file content line-by-line
        for raw_line in content.splitlines():
            line = raw_line.strip()

            ## Skip blank lines
            if not line:
                continue

            ## Handle comments (# or ;)
            if line.startswith("#") or line.startswith(";"):
                ## Check for node annotation comments like "# Node: my-server"
                if "node:" in line.lower():
                    current_comment = line.split(":", 1)[1].strip()
                continue

            ## Section header parsing (e.g. [Interface] or [Peer])
            if line.startswith("[") and line.endswith("]"):
                header = line[1:-1].strip().lower()
                if header == "interface":
                    current_section = "interface"
                elif header == "peer":
                    ## If a peer block was already being populated, save it before starting new one
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

            ## Key = Value directive lines
            if "=" in line:
                key, val = [p.strip() for p in line.split("=", 1)]
                key_lower = key.lower()

                ## Parse directives inside [Interface] section
                if current_section == "interface":
                    if key_lower == "privatekey":
                        interface_params["private_key"] = val
                    elif key_lower == "address":
                        ## Handle comma-separated list of addresses
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

                ## Parse directives inside [Peer] section
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

        ## Flush final pending peer after end of loop
        if current_peer_params is not None:
            peers.append(MeshAuditor._build_peer(current_peer_params))

        ## Construct InterfaceConfig and return complete WireGuardConfig
        interface = InterfaceConfig(**interface_params)
        return WireGuardConfig(interface=interface, peers=peers)

    @staticmethod
    def _build_peer(params: Dict[str, Any]) -> PeerConfig:
        """Helper to instantiate PeerConfig from parsed parameter dictionary."""
        return PeerConfig(
            public_key=params["public_key"],
            allowed_ips=params["allowed_ips"],
            endpoint=params["endpoint"],
            preshared_key=params["preshared_key"],
            persistent_keepalive=params["persistent_keepalive"],
            comment=params.get("comment"),
        )
