# ==============================================================================
# Program: meshguard/cli.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Command-line interface dispatcher supporting mesh blueprint initialization,
#          pure-Python key generation, configuration compilation, routing collision
#          auditing, topology visualization, and Linux systemd service unit export.
# ==============================================================================

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## Command-line argument parsing library
"""MeshGuard command-line interface: init, keygen, generate, audit, visualize and systemd export subcommands."""

# Role: console entry point (python -m meshguard / the `meshguard` script). Each
# cmd_* function below is one subcommand; they call into crypto (keys), generator
# (blueprint -> .conf files), auditor (collision/MTU/key checks) and visualizer.
# Exit codes: 0 success, 1 any error or an audit with CRITICAL/ERROR findings, so
# the audit subcommand can gate CI or a deploy script.
# Zero third-party dependencies: key generation is done in pure Python.
import argparse
## JSON data serialization and parsing
import json
## Object-oriented filesystem path manipulation
from pathlib import Path
## System module for process exit codes and standard error streams
import sys
## Type hinting annotations
from typing import List, Optional

## ---------------------------------------------------------------------------
## Internal Model, Cryptographic & Orchestration Imports
## ---------------------------------------------------------------------------
from meshguard.crypto import (
    generate_keypair,
    generate_preshared_key,
    derive_public_key,
    validate_key_format,
)
from meshguard.generator import MeshGenerator
from meshguard.auditor import MeshAuditor
from meshguard.visualizer import MeshVisualizer
from meshguard.models import TopologyType, AuditSeverity


def build_parser() -> argparse.ArgumentParser:
    """Builds the top-level argument parser with subcommands."""
    ## Create root CLI argument parser
    parser = argparse.ArgumentParser(
        prog="meshguard",
        description=(
            "MeshGuard: Zero-dependency WireGuard mesh configuration synthesizer, "
            "topology visualizer, and subnet collision audit engine."
        ),
    )
    ## Create subparser collection for distinct CLI actions
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    ## -----------------------------------------------------------------------
    ## Subcommand: init
    ## -----------------------------------------------------------------------
    init_parser = subparsers.add_parser("init", help="Generate a starter mesh blueprint JSON file")
    init_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="mesh.json",
        help="Destination path for blueprint JSON (default: mesh.json)",
    )
    init_parser.add_argument(
        "--topology",
        "-t",
        choices=["full_mesh", "hub_and_spoke"],
        default="full_mesh",
        help="Network topology structure (default: full_mesh)",
    )
    init_parser.add_argument(
        # Minimum is enforced in cmd_init, not here, so `--nodes 1` is silently raised to 2.
        "--nodes",
        "-n",
        type=int,
        default=3,
        help="Number of initial sample nodes to create (default: 3)",
    )

    ## -----------------------------------------------------------------------
    ## Subcommand: keygen
    ## -----------------------------------------------------------------------
    keygen_parser = subparsers.add_parser(
        "keygen",
        help="Generate Curve25519 WireGuard keypairs or PresharedKeys in pure Python",
    )
    keygen_parser.add_argument(
        "--psk",
        action="store_true",
        help="Generate a 32-byte symmetric PresharedKey (PSK) instead of a keypair",
    )
    keygen_parser.add_argument(
        # Lets an operator recompute the public key for a private key they already have,
        # e.g. to fill in a peer's blueprint entry. The private key appears in shell history
        # when passed this way (known trade-off of a CLI argument).
        "--derive-public",
        type=str,
        metavar="PRIVATE_KEY",
        help="Derive public key from an existing Base64 private key",
    )

    ## -----------------------------------------------------------------------
    ## Subcommand: generate
    ## -----------------------------------------------------------------------
    gen_parser = subparsers.add_parser(
        "generate",
        help="Synthesize synchronized WireGuard configs from a mesh blueprint",
    )
    gen_parser.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Path to declarative mesh blueprint JSON file",
    )
    gen_parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="./wg-configs",
        help="Output directory for generated configuration files (default: ./wg-configs)",
    )
    gen_parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="wg0",
        help="WireGuard interface name (default: wg0)",
    )
    gen_parser.add_argument(
        "--no-systemd",
        action="store_true",
        help="Omit generating systemd service and networkd units",
    )

    ## -----------------------------------------------------------------------
    ## Subcommand: audit
    ## -----------------------------------------------------------------------
    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit configurations or blueprints for subnet collisions, MTU risks, and key errors",
    )
    # Exactly one audit target must be named: a blueprint (checked before configs are
    # generated), one rendered .conf, or a whole directory of rendered .conf files.
    audit_group = audit_parser.add_mutually_exclusive_group(required=True)
    audit_group.add_argument(
        "--config",
        "-c",
        type=str,
        help="Audit a declarative mesh blueprint JSON file",
    )
    audit_group.add_argument(
        "--dir",
        "-d",
        type=str,
        help="Audit all *.conf files in a directory",
    )
    audit_group.add_argument(
        "--file",
        "-f",
        type=str,
        help="Audit a single WireGuard configuration file",
    )

    ## -----------------------------------------------------------------------
    ## Subcommand: visualize
    ## -----------------------------------------------------------------------
    vis_parser = subparsers.add_parser(
        "visualize",
        help="Render ASCII topology diagrams and routing matrices in terminal",
    )
    vis_parser.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Path to declarative mesh blueprint JSON file",
    )

    ## -----------------------------------------------------------------------
    ## Subcommand: export-systemd
    ## -----------------------------------------------------------------------
    sysd_parser = subparsers.add_parser(
        "export-systemd",
        help="Print hardened Linux systemd service unit template for an interface",
    )
    sysd_parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="wg0",
        help="Interface name (default: wg0)",
    )

    ## Return fully wired parser
    return parser


def cmd_init(args: argparse.Namespace) -> int:
    """Creates a starter blueprint with freshly generated keys."""
    out_path = Path(args.output)

    ## Guard against accidental overwrite of an existing blueprint
    # Never clobber: a blueprint holds private keys, and overwriting it would
    # silently orphan the keys already deployed to peers.
    if out_path.exists():
        print(f"Error: Target file '{out_path}' already exists. Refusing to overwrite.", file=sys.stderr)
        return 1

    nodes = []
    ## Guarantee a minimum of 2 nodes for meaningful mesh networking
    # A mesh needs at least two peers to have any link.
    num_nodes = max(2, args.nodes)

    ## Generate sample nodes with fresh Curve25519 keypairs
    for i in range(1, num_nodes + 1):
        priv, pub = generate_keypair()
        # In hub_and_spoke the first node is the hub; in full_mesh nobody is.
        is_hub = (args.topology == "hub_and_spoke" and i == 1)
        node_def = {
            "name": f"node-{i:02d}" if not is_hub else "hub-gateway",
            # Private IPv4 (10.100.0.0/24) plus an IPv6 ULA (fd00:42::/64) inside the tunnel.
            "mesh_ips": [f"10.100.0.{i}/24", f"fd00:42::{i}/64"],
            # Only nodes that must be dialled get an endpoint: every node in a full mesh, but
            # in hub_and_spoke just the hub (spokes only dial out, so they need no public endpoint).
            # vpn.example.com is a placeholder to be edited; ports increment per node so the
            # sample works if all nodes run on one host.
            "endpoint": f"vpn.example.com:{51820 + i - 1}" if (is_hub or args.topology == "full_mesh") else None,
            "listen_port": 51820,
            "private_key": priv,
            "public_key": pub,
            "is_hub": is_hub,
            # The hub advertises a sample LAN behind it, showing how routed subnets are declared.
            "extra_allowed_ips": [] if not is_hub else ["192.168.10.0/24"],
            # 1420 = 1500 Ethernet minus 80 bytes of WireGuard overhead (worst case, IPv6 outer).
            "mtu": 1420,
            "dns": ["1.1.1.1", "8.8.8.8"] if not is_hub else [],
        }
        nodes.append(node_def)

    ## Assemble sample declarative mesh blueprint dictionary
    sample_mesh = {
        "network_name": "homelab-mesh",
        "topology": args.topology,
        "default_mtu": 1420,
        "default_port": 51820,
        # One shared PSK adds a symmetric layer on top of Curve25519 (post-quantum hedge).
        "global_preshared_key": generate_preshared_key(),
        "nodes": nodes,
    }

    ## Write formatted JSON to the designated output path
    # The file contains private keys in plain text: keep it out of version control.
    out_path.write_text(json.dumps(sample_mesh, indent=2) + "\n", encoding="utf-8")
    print(f"✓ Initialized sample {args.topology} blueprint with {num_nodes} nodes at: {out_path}")
    print("  Run 'meshguard visualize --config mesh.json' to view topology.")
    print("  Run 'meshguard generate --config mesh.json' to compile .conf files.")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Handles key generation and derivation."""
    # Mode precedence: --psk first, then --derive-public, otherwise a fresh keypair.
    ## 1. PresharedKey generation mode
    if args.psk:
        psk = generate_preshared_key()
        print(f"PresharedKey = {psk}")
        return 0

    ## 2. Public key derivation mode
    if args.derive_public:
        priv = args.derive_public.strip()
        try:
            pub = derive_public_key(priv)
            print(f"PublicKey = {pub}")
            return 0
        except Exception as e:
            print(f"Error deriving public key: {e}", file=sys.stderr)
            return 1

    ## 3. Standard synchronized keypair generation mode
    priv, pub = generate_keypair()
    print(f"PrivateKey = {priv}")
    print(f"PublicKey  = {pub}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Compiles a mesh blueprint into deployment files."""
    ## Load and parse declarative blueprint
    try:
        gen = MeshGenerator.from_json_file(args.config)
    except Exception as e:
        print(f"Error loading mesh blueprint '{args.config}': {e}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir)
    include_systemd = not args.no_systemd

    ## Execute file export
    # export_configs writes one .conf per node (plus optional systemd/networkd units)
    # and returns {node name: path}. I/O errors here propagate as exceptions.
    results = gen.export_configs(
        output_dir=out_dir,
        interface_name=args.interface,
        include_systemd_units=include_systemd,
    )

    ## Print compilation summary
    print(f"✓ Successfully synthesized WireGuard mesh '{gen.config.network_name}':")
    print(f"  Topology: {gen.config.topology.value}")
    print(f"  Interface: {args.interface}")
    print(f"  Output directory: {out_dir.resolve()}")
    print("")
    for node_name, path in results.items():
        print(f"  • {node_name:<16} -> {path}")

    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Executes diagnostic audit suite."""
    auditor = MeshAuditor()
    findings = []

    ## Case 1: Audit high-level JSON blueprint
    if args.config:
        try:
            gen = MeshGenerator.from_json_file(args.config)
            findings = auditor.audit_mesh_config(gen.config)
        except Exception as e:
            print(f"Failed to audit blueprint: {e}", file=sys.stderr)
            return 1

    ## Case 2: Audit individual .conf file
    elif args.file:
        try:
            wg_conf = auditor.parse_wg_conf_file(args.file)
            findings = auditor.audit_wireguard_config(wg_conf, file_path=args.file)
        except Exception as e:
            print(f"Failed to audit config file: {e}", file=sys.stderr)
            return 1

    ## Case 3: Audit directory of .conf files
    elif args.dir:
        try:
            findings = auditor.audit_directory(args.dir)
        except Exception as e:
            print(f"Failed to audit directory: {e}", file=sys.stderr)
            return 1

    ## Clean audit result
    if not findings:
        print("✓ All audit checks passed! No subnet collisions, key faults, or MTU anomalies detected.")
        return 0

    ## Compute summary metrics by severity
    # Counts by severity drive both the summary line and the exit code below.
    critical_count = sum(1 for f in findings if f.severity == AuditSeverity.CRITICAL)
    error_count = sum(1 for f in findings if f.severity == AuditSeverity.ERROR)
    warn_count = sum(1 for f in findings if f.severity == AuditSeverity.WARNING)
    info_count = sum(1 for f in findings if f.severity == AuditSeverity.INFO)

    print("=" * 70)
    print(f" AUDIT FINDINGS ({len(findings)} issues found)")
    print(f" CRITICAL: {critical_count} | ERROR: {error_count} | WARNING: {warn_count} | INFO: {info_count}")
    print("=" * 70)

    ## Print individual findings
    for f in findings:
        print(f.to_display_string())
        print("-" * 70)

    ## Fail with non-zero exit code if CRITICAL or ERROR findings exist
    # Warnings and info are advisory only; CRITICAL and ERROR fail the command (exit 1).
    if critical_count > 0 or error_count > 0:
        return 1
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    """Renders ASCII visual diagrams."""
    ## Load blueprint
    try:
        gen = MeshGenerator.from_json_file(args.config)
    except Exception as e:
        print(f"Error loading mesh blueprint: {e}", file=sys.stderr)
        return 1

    ## Render diagnostic visuals
    visualizer = MeshVisualizer(gen.config)
    print(visualizer.render_all())
    return 0


def cmd_export_systemd(args: argparse.Namespace) -> int:
    """Prints systemd service unit template."""
    ## Generate production systemd unit string
    unit = MeshGenerator.generate_systemd_service_unit(args.interface)
    print(unit)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    ## Build argument parser and parse incoming arguments
    parser = build_parser()
    args = parser.parse_args(argv)

    ## If no subcommand specified, display help and return cleanly
    if not args.command:
        parser.print_help()
        return 0

    ## Dispatch to appropriate command handler
    if args.command == "init":
        return cmd_init(args)
    elif args.command == "keygen":
        return cmd_keygen(args)
    elif args.command == "generate":
        return cmd_generate(args)
    elif args.command == "audit":
        return cmd_audit(args)
    elif args.command == "visualize":
        return cmd_visualize(args)
    elif args.command == "export-systemd":
        return cmd_export_systemd(args)

    return 0


if __name__ == "__main__":
    ## Execute entrypoint when run as standalone script
    sys.exit(main())
