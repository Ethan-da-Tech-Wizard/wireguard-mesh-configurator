# Program: wireguard-mesh-configurator - __init__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Expose primary public API classes and functions for MeshGuard, a zero-dependency WireGuard mesh orchestrator, auditor, and visualizer.

"""
Expose primary public API classes and functions for MeshGuard, a zero-dependency WireGuard mesh orchestrator, auditor, and visualizer.
"""

## ---------------------------------------------------------------------------
## Import core data models representing WireGuard configurations, network
## topologies, and audit diagnostic findings.
## ---------------------------------------------------------------------------
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

## ---------------------------------------------------------------------------
## Import pure-Python RFC 7748 Curve25519 cryptographic primitives and helpers
## for keypair generation, public key derivation, and validation.
## ---------------------------------------------------------------------------
from meshguard.crypto import (
    clamp_scalar,
    derive_public_key,
    generate_keypair,
    generate_preshared_key,
    generate_private_key,
    validate_key_format,
    x25519_scalar_mult,
)

## ---------------------------------------------------------------------------
## Import orchestration engines:
## - MeshGenerator: Compiles declarative mesh topologies into config files.
## - MeshAuditor: Analyzes configuration files for routing collisions and errors.
## - MeshVisualizer: Renders ASCII topology diagrams and routing matrices.
## ---------------------------------------------------------------------------
from meshguard.generator import MeshGenerator
from meshguard.auditor import MeshAuditor
from meshguard.visualizer import MeshVisualizer

## ---------------------------------------------------------------------------
## Package metadata declarations
## ---------------------------------------------------------------------------
## Semantic version string for release tracking
__version__ = "0.1.0"
## Author attribution and copyright ownership
__author__ = "Ethan Kilmer"
## Open-source software license descriptor
__license__ = "MIT"

## ---------------------------------------------------------------------------
## Explicit export list defining public symbols available upon wildcard import
## ---------------------------------------------------------------------------
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
