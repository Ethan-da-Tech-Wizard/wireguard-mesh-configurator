"""
MeshGuard - Zero-Dependency WireGuard Mesh Configurator, Auditor, and Visualizer.

A pure-Python (Python 3.8+ standard library only) suite designed for sysadmins,
homelabbers, and DevOps teams to orchestrate and audit decentralized WireGuard networks.

Key Capabilities:
-----------------
1. Mesh Topology Synthesizer:
   Generates mathematically synchronized configuration files for Full-Mesh (O(N^2) links)
   and Hub-and-Spoke (relay) network topologies.

2. Cryptokey Routing Collision Detector:
   Audits AllowedIPs across interfaces to guarantee zero Radix trie collisions
   or IP address overlaps that cause packet drops or silent route hijacking.

3. Path MTU (PMTU) & Encapsulation Verifier:
   Calculates overhead for IPv4/IPv6/UDP/WireGuard headers to prevent fragmentation
   and blackholes (flags MTU > 1420 or < 1280).

4. Pure Python RFC 7748 X25519 Cryptography:
   Generates, validates, and derives Curve25519 public keys without external libraries
   or binary dependencies.

5. Production Linux Systemd Exporter:
   Generates both wg-quick@wg0.service systemd units and native systemd-networkd
   (.netdev + .network) interface templates.
"""

from meshguard.models import (
    AuditFinding,
    AuditSeverity,
    InterfaceConfig,
    MeshConfig,
    Node,
    PeerConfig,
    TopologyType,
    WireGuardConfig,
)
from meshguard.crypto import (
    clamp_scalar,
    derive_public_key,
    generate_keypair,
    generate_preshared_key,
    generate_private_key,
    validate_key_format,
    x25519_scalar_mult,
)
from meshguard.generator import MeshGenerator
from meshguard.auditor import MeshAuditor
from meshguard.visualizer import MeshVisualizer

__version__ = "0.1.0"
__author__ = "Ethan Kilmer"
__license__ = "MIT"

__all__ = [
    "AuditFinding",
    "AuditSeverity",
    "InterfaceConfig",
    "MeshAuditor",
    "MeshConfig",
    "MeshGenerator",
    "MeshVisualizer",
    "Node",
    "PeerConfig",
    "TopologyType",
    "WireGuardConfig",
    "clamp_scalar",
    "derive_public_key",
    "generate_keypair",
    "generate_preshared_key",
    "generate_private_key",
    "validate_key_format",
    "x25519_scalar_mult",
]
