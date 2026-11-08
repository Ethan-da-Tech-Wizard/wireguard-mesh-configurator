"""
test_meshguard - Exhaustive Unit Test Suite for MeshGuard.

Tests:
1. Crypto: RFC 7748 X25519 scalar mult, keypair generation, bit clamping, PSK, key validation.
2. Models: Serialization to wg-quick format, systemd-networkd generation, CIDR host masking.
3. Generator: Full-mesh synthesis, Hub-and-Spoke synthesis, NAT keepalive injection, file export.
4. Auditor: Cryptokey Radix trie collision detection, duplicate IPs, MTU bounds, key mismatches, config parser.
5. Visualizer: Terminal graph, node inventory table, routing matrix.
6. CLI: Subcommands (init, keygen, generate, audit, visualize, export-systemd).
"""

import base64
import binascii
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from meshguard.crypto import (
    clamp_scalar,
    derive_public_key,
    generate_keypair,
    generate_preshared_key,
    generate_private_key,
    validate_key_format,
    x25519_scalar_mult,
)
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
from meshguard.generator import MeshGenerator
from meshguard.auditor import MeshAuditor
from meshguard.visualizer import MeshVisualizer
from meshguard.cli import main


class TestCrypto(unittest.TestCase):
    """Verifies RFC 7748 Curve25519 and WireGuard key handling."""

    def test_bit_clamping(self):
        """Checks RFC 7748 bit clamping rules (clearing bits 0,1,2,255 and setting bit 254)."""
        raw = bytearray([0xFF] * 32)
        clamped = clamp_scalar(bytes(raw))

        # Bit 0, 1, 2 must be 0 (masked with 0xF8 = 248)
        self.assertEqual(clamped[0], 0xF8)
        # Bit 255 must be 0, Bit 254 must be 1 (0x7F & 0xFF | 0x40 = 0x40 | 0x7F = 0x7F & ~0x80 | 0x40 = 0x40 | 0x3F = 0x7F... wait:
        # byte 31: 0xFF & 127 = 0x7F (01111111). 0x7F | 64 = 0x7F (01111111)
        self.assertEqual(clamped[31], 127)

        # Test with all zeros
        zero_raw = bytearray([0x00] * 32)
        zero_clamped = clamp_scalar(bytes(zero_raw))
        self.assertEqual(zero_clamped[0], 0x00)
        self.assertEqual(zero_clamped[31], 64)  # bit 254 is set

    def test_rfc7748_alice_vector(self):
        """Verifies scalar multiplication against RFC 7748 Section 6.1 Alice test vector."""
        alice_priv_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        alice_priv_bytes = clamp_scalar(binascii.unhexlify(alice_priv_hex))
        alice_pub = x25519_scalar_mult(alice_priv_bytes, 9)

        expected_pub_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        self.assertEqual(binascii.hexlify(alice_pub).decode(), expected_pub_hex)

    def test_keypair_generation_and_derivation(self):
        """Ensures generated keys are valid and public key is deterministically derivable."""
        priv, pub = generate_keypair()

        # Validate formats
        valid_priv, msg_priv = validate_key_format(priv)
        self.assertTrue(valid_priv, msg_priv)

        valid_pub, msg_pub = validate_key_format(pub)
        self.assertTrue(valid_pub, msg_pub)

        # Ensure public key derived from private key matches exactly
        derived = derive_public_key(priv)
        self.assertEqual(derived, pub)

    def test_preshared_key(self):
        """Verifies PSK generation and format."""
        psk = generate_preshared_key()
        valid, msg = validate_key_format(psk)
        self.assertTrue(valid, msg)

    def test_validate_key_format_invalid_inputs(self):
        """Tests rejection of malformed keys."""
        # Non-string
        valid, _ = validate_key_format(12345)  # type: ignore
        self.assertFalse(valid)

        # Invalid length
        valid, _ = validate_key_format("too-short=")
        self.assertFalse(valid)

        # Invalid base64 characters
        valid, _ = validate_key_format("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA*")
        self.assertFalse(valid)

        # Null/zero key
        zero_key = base64.b64encode(b"\x00" * 32).decode()
        valid, msg = validate_key_format(zero_key)
        self.assertFalse(valid)
        self.assertIn("placeholder", msg)

        # Placeholder 'AAA...' key
        dummy_key = "A" * 43 + "="
        valid, msg = validate_key_format(dummy_key)
        self.assertFalse(valid)


class TestModels(unittest.TestCase):
    """Verifies WireGuard dataclasses and serialization."""

    def test_wg_quick_block_serialization(self):
        """Tests serialization to wg-quick format."""
        iface = InterfaceConfig(
            private_key="a" * 43 + "=",
            addresses=["10.100.0.1/24", "fd00:mesh::1/64"],
            listen_port=51820,
            mtu=1420,
            dns=["1.1.1.1"],
            post_up=["iptables -A FORWARD -i wg0 -j ACCEPT"],
        )
        peer = PeerConfig(
            public_key="b" * 43 + "=",
            allowed_ips=["10.100.0.2/32"],
            endpoint="198.51.100.2:51820",
            persistent_keepalive=25,
            comment="peer-02",
        )
        config = WireGuardConfig(interface=iface, peers=[peer])

        serialized = config.to_wg_quick()
        self.assertIn("[Interface]", serialized)
        self.assertIn(f"PrivateKey = {iface.private_key}", serialized)
        self.assertIn("Address = 10.100.0.1/24", serialized)
        self.assertIn("ListenPort = 51820", serialized)
        self.assertIn("MTU = 1420", serialized)
        self.assertIn("DNS = 1.1.1.1", serialized)
        self.assertIn("PostUp = iptables -A FORWARD -i wg0 -j ACCEPT", serialized)
        self.assertIn("[Peer]", serialized)
        self.assertIn(f"PublicKey = {peer.public_key}", serialized)
        self.assertIn("Endpoint = 198.51.100.2:51820", serialized)
        self.assertIn("AllowedIPs = 10.100.0.2/32", serialized)
        self.assertIn("PersistentKeepalive = 25", serialized)

    def test_systemd_networkd_generation(self):
        """Tests generation of systemd-networkd .netdev and .network files."""
        iface = InterfaceConfig(
            private_key="a" * 43 + "=",
            addresses=["10.100.0.1/24"],
            listen_port=51820,
            mtu=1420,
        )
        peer = PeerConfig(
            public_key="b" * 43 + "=",
            allowed_ips=["10.100.0.2/32"],
            endpoint="198.51.100.2:51820",
        )
        config = WireGuardConfig(interface=iface, peers=[peer])

        files = config.to_systemd_networkd("wg0")
        self.assertIn("wg0.netdev", files)
        self.assertIn("wg0.network", files)

        netdev = files["wg0.netdev"]
        self.assertIn("Kind=wireguard", netdev)
        self.assertIn("[WireGuardPeer]", netdev)

        network = files["wg0.network"]
        self.assertIn("Address=10.100.0.1/24", network)
        self.assertIn("MTUBytes=1420", network)

    def test_node_routable_ips(self):
        """Verifies conversion of mesh subnet IPs to host /32 or /128 masks."""
        node = Node(
            name="gateway",
            mesh_ips=["10.100.0.1/24", "fd00:42::1/64"],
            public_key="k" * 43 + "=",
            extra_allowed_ips=["192.168.1.0/24"],
        )
        routable = node.get_all_routable_ips()
        self.assertIn("10.100.0.1/32", routable)
        self.assertIn("fd00:42::1/128", routable)
        self.assertIn("192.168.1.0/24", routable)


class TestGenerator(unittest.TestCase):
    """Verifies mesh generation algorithms."""

    def setUp(self):
        self.priv1, self.pub1 = generate_keypair()
        self.priv2, self.pub2 = generate_keypair()
        self.priv3, self.pub3 = generate_keypair()

    def test_full_mesh_generation(self):
        """Checks full-mesh pairwise peering across 3 nodes."""
        nodes = [
            Node(
                name="node-01",
                mesh_ips=["10.100.0.1/24"],
                public_key=self.pub1,
                private_key=self.priv1,
                endpoint="vpn1.example.com:51820",
            ),
            Node(
                name="node-02",
                mesh_ips=["10.100.0.2/24"],
                public_key=self.pub2,
                private_key=self.priv2,
                endpoint="vpn2.example.com:51820",
            ),
            Node(
                name="node-03",
                mesh_ips=["10.100.0.3/24"],
                public_key=self.pub3,
                private_key=self.priv3,
                endpoint=None,  # Behind NAT
            ),
        ]
        mesh = MeshConfig(network_name="test-mesh", topology=TopologyType.FULL_MESH, nodes=nodes)
        gen = MeshGenerator(mesh)
        configs = gen.generate_all()

        self.assertEqual(len(configs), 3)

        # node-01 should have 2 peers (node-02 and node-03)
        conf1 = configs["node-01"]
        self.assertEqual(len(conf1.peers), 2)
        peer_keys = [p.public_key for p in conf1.peers]
        self.assertIn(self.pub2, peer_keys)
        self.assertIn(self.pub3, peer_keys)

        # node-03 (behind NAT) connecting to node-01 (has endpoint) should have keepalive 25
        conf3 = configs["node-03"]
        peer_to_1 = [p for p in conf3.peers if p.public_key == self.pub1][0]
        self.assertEqual(peer_to_1.persistent_keepalive, 25)

    def test_hub_and_spoke_generation(self):
        """Checks hub-and-spoke routing where spoke traffic relays through hub."""
        nodes = [
            Node(
                name="hub",
                mesh_ips=["10.100.0.1/24"],
                public_key=self.pub1,
                private_key=self.priv1,
                endpoint="hub.example.com:51820",
                is_hub=True,
            ),
            Node(
                name="spoke-01",
                mesh_ips=["10.100.0.2/24"],
                public_key=self.pub2,
                private_key=self.priv2,
                is_hub=False,
            ),
            Node(
                name="spoke-02",
                mesh_ips=["10.100.0.3/24"],
                public_key=self.pub3,
                private_key=self.priv3,
                is_hub=False,
            ),
        ]
        mesh = MeshConfig(
            network_name="hub-mesh",
            topology=TopologyType.HUB_AND_SPOKE,
            nodes=nodes,
        )
        gen = MeshGenerator(mesh)
        configs = gen.generate_all()

        # Hub connects to spoke-01 and spoke-02 (2 peers)
        hub_conf = configs["hub"]
        self.assertEqual(len(hub_conf.peers), 2)

        # Spoke-01 connects ONLY to Hub (1 peer)
        spoke1_conf = configs["spoke-01"]
        self.assertEqual(len(spoke1_conf.peers), 1)
        hub_peer = spoke1_conf.peers[0]
        self.assertEqual(hub_peer.public_key, self.pub1)

        # The hub peer on spoke-01 MUST include spoke-02's IP so it routes through hub!
        self.assertIn("10.100.0.1/32", hub_peer.allowed_ips)
        self.assertIn("10.100.0.3/32", hub_peer.allowed_ips)

    def test_export_configs(self):
        """Tests exporting configurations and systemd units to disk."""
        nodes = [
            Node(
                name="node-a",
                mesh_ips=["10.100.0.1/24"],
                public_key=self.pub1,
                private_key=self.priv1,
                endpoint="node-a.com:51820",
            ),
            Node(
                name="node-b",
                mesh_ips=["10.100.0.2/24"],
                public_key=self.pub2,
                private_key=self.priv2,
                endpoint="node-b.com:51820",
            ),
        ]
        mesh = MeshConfig(network_name="export-mesh", nodes=nodes)
        gen = MeshGenerator(mesh)

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = gen.export_configs(tmpdir, interface_name="wg0", include_systemd_units=True)
            self.assertEqual(len(paths), 2)
            self.assertTrue(paths["node-a"].exists())
            self.assertTrue(paths["node-b"].exists())

            # Check that systemd units exist
            node_a_dir = Path(tmpdir) / "node-a"
            self.assertTrue((node_a_dir / "wg-quick@wg0.service").exists())
            self.assertTrue((node_a_dir / "systemd-networkd" / "wg0.netdev").exists())
            self.assertTrue((node_a_dir / "systemd-networkd" / "wg0.network").exists())


class TestAuditor(unittest.TestCase):
    """Verifies audit checks, collision detection, and MTU verification."""

    def setUp(self):
        self.priv1, self.pub1 = generate_keypair()
        self.priv2, self.pub2 = generate_keypair()

    def test_allowed_ips_collision_on_interface(self):
        """Detects overlapping AllowedIPs across peers on the same interface."""
        iface = InterfaceConfig(private_key=self.priv1, addresses=["10.100.0.1/24"])
        # Peer 1 claims 10.0.0.0/24
        p1 = PeerConfig(public_key=self.pub1, allowed_ips=["10.0.0.0/24"])
        # Peer 2 claims 10.0.0.5/32 (COLLISION!)
        p2 = PeerConfig(public_key=self.pub2, allowed_ips=["10.0.0.5/32"])

        config = WireGuardConfig(interface=iface, peers=[p1, p2])
        auditor = MeshAuditor()
        findings = auditor.audit_wireguard_config(config)

        collisions = [f for f in findings if f.rule_id == "COLLISION-001"]
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0].severity, AuditSeverity.CRITICAL)

    def test_duplicate_mesh_ip_allocation(self):
        """Detects duplicate IP allocation in declarative mesh blueprint."""
        nodes = [
            Node(name="box1", mesh_ips=["10.100.0.1/24"], public_key=self.pub1),
            Node(name="box2", mesh_ips=["10.100.0.1/24"], public_key=self.pub2),  # Duplicate!
        ]
        mesh = MeshConfig(network_name="collision-mesh", nodes=nodes)
        auditor = MeshAuditor()
        findings = auditor.audit_mesh_config(mesh)

        dups = [f for f in findings if f.rule_id == "IP-001"]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0].severity, AuditSeverity.CRITICAL)

    def test_mtu_boundaries(self):
        """Verifies MTU < 1280 (ERROR) and MTU == 1500 (WARNING)."""
        auditor = MeshAuditor()

        # MTU < 1280
        auditor._audit_mtu(1200, "test-target")
        self.assertTrue(any(f.rule_id == "MTU-001" and f.severity == AuditSeverity.ERROR for f in auditor.findings))

        # MTU == 1500
        auditor.findings.clear()
        auditor._audit_mtu(1500, "test-target")
        self.assertTrue(any(f.rule_id == "MTU-002" and f.severity == AuditSeverity.WARNING for f in auditor.findings))

        # MTU == 1420 (Valid)
        auditor.findings.clear()
        auditor._audit_mtu(1420, "test-target")
        self.assertEqual(len(auditor.findings), 0)

    def test_key_mismatch_detection(self):
        """Detects when declared public key does not match derived private key."""
        other_priv, other_pub = generate_keypair()
        nodes = [
            Node(
                name="mismatched-node",
                mesh_ips=["10.100.0.1/24"],
                private_key=self.priv1,
                public_key=other_pub,  # Mismatch!
            )
        ]
        mesh = MeshConfig(network_name="mismatch-mesh", nodes=nodes)
        auditor = MeshAuditor()
        findings = auditor.audit_mesh_config(mesh)

        mismatches = [f for f in findings if f.rule_id == "KEY-003"]
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0].severity, AuditSeverity.CRITICAL)

    def test_parse_wg_conf(self):
        """Tests parsing raw configuration file string."""
        sample_conf = f"""
# WireGuard Test Conf
[Interface]
PrivateKey = {self.priv1}
Address = 10.100.0.1/24, fd00::1/64
ListenPort = 51820
MTU = 1420
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Node: peer-server
[Peer]
PublicKey = {self.pub2}
AllowedIPs = 10.100.0.2/32, 192.168.50.0/24
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25
"""
        config = MeshAuditor.parse_wg_conf(sample_conf)
        self.assertEqual(config.interface.private_key, self.priv1)
        self.assertEqual(len(config.interface.addresses), 2)
        self.assertEqual(config.interface.listen_port, 51820)
        self.assertEqual(config.interface.mtu, 1420)
        self.assertEqual(len(config.peers), 1)

        peer = config.peers[0]
        self.assertEqual(peer.public_key, self.pub2)
        self.assertEqual(len(peer.allowed_ips), 2)
        self.assertEqual(peer.endpoint, "203.0.113.10:51820")
        self.assertEqual(peer.persistent_keepalive, 25)
        self.assertEqual(peer.comment, "peer-server")

    def test_endpoint_and_port_auditing(self):
        """Checks validation of endpoints and UDP port numbers."""
        auditor = MeshAuditor()

        # Missing port
        auditor._audit_endpoint("vpn.example.com", "test-ep")
        self.assertTrue(any(f.rule_id == "EP-001" for f in auditor.findings))

        # Port out of range
        auditor.findings.clear()
        auditor._audit_endpoint("vpn.example.com:70000", "test-ep")
        self.assertTrue(any(f.rule_id == "EP-004" for f in auditor.findings))

        # Valid IPv6 endpoint
        auditor.findings.clear()
        auditor._audit_endpoint("[2001:db8::1]:51820", "test-ep")
        self.assertEqual(len(auditor.findings), 0)

    def test_file_permission_audit(self):
        """Detects insecure (group/world-readable) file permissions."""
        with tempfile.NamedTemporaryFile(suffix=".conf") as tf:
            path = Path(tf.name)
            path.chmod(0o644)  # Insecure permissions
            auditor = MeshAuditor()
            auditor._audit_file_permissions(path)
            self.assertTrue(any(f.rule_id == "SEC-001" and f.severity == AuditSeverity.CRITICAL for f in auditor.findings))

            # Chmod 600 should pass cleanly
            path.chmod(0o600)
            auditor.findings.clear()
            auditor._audit_file_permissions(path)
            self.assertEqual(len(auditor.findings), 0)


class TestVisualizer(unittest.TestCase):
    """Verifies ASCII rendering routines."""

    def test_render_all(self):
        """Checks visual output formatting without exceptions."""
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        nodes = [
            Node(name="edge-01", mesh_ips=["10.100.0.1/24"], public_key=pub1, endpoint="1.1.1.1:51820", is_hub=True),
            Node(name="edge-02", mesh_ips=["10.100.0.2/24"], public_key=pub2, endpoint=None, is_hub=False),
        ]
        mesh = MeshConfig(network_name="vis-test", topology=TopologyType.HUB_AND_SPOKE, nodes=nodes)
        vis = MeshVisualizer(mesh)
        output = vis.render_all()

        self.assertIn("WIREGUARD MESH TOPOLOGY", output)
        self.assertIn("NODE INVENTORY", output)
        self.assertIn("CONNECTIVITY DIAGRAM", output)
        self.assertIn("ROUTING PATH MATRIX", output)
        self.assertIn("edge-01", output)
        self.assertIn("edge-02", output)


class TestCLI(unittest.TestCase):
    """Verifies CLI execution pathways."""

    def test_cli_init_and_generate_and_audit(self):
        """End-to-end integration test of init -> visualize -> generate -> audit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mesh_json = Path(tmpdir) / "mesh.json"
            out_dir = Path(tmpdir) / "configs"

            # 1. Init
            rc_init = main(["init", "--output", str(mesh_json), "--nodes", "3"])
            self.assertEqual(rc_init, 0)
            self.assertTrue(mesh_json.exists())

            # 2. Visualize
            rc_vis = main(["visualize", "--config", str(mesh_json)])
            self.assertEqual(rc_vis, 0)

            # 3. Generate
            rc_gen = main(["generate", "--config", str(mesh_json), "--output-dir", str(out_dir)])
            self.assertEqual(rc_gen, 0)
            self.assertTrue((out_dir / "node-01" / "wg0.conf").exists())

            # 4. Audit generated directory
            rc_audit = main(["audit", "--dir", str(out_dir)])
            self.assertEqual(rc_audit, 0)

    def test_cli_keygen(self):
        """Verifies CLI keygen commands."""
        # Test keypair generation
        rc_key = main(["keygen"])
        self.assertEqual(rc_key, 0)

        # Test PSK generation
        rc_psk = main(["keygen", "--psk"])
        self.assertEqual(rc_psk, 0)

        # Test public key derivation
        priv, pub = generate_keypair()
        rc_derive = main(["keygen", "--derive-public", priv])
        self.assertEqual(rc_derive, 0)

    def test_cli_export_systemd(self):
        """Verifies CLI export-systemd command."""
        rc_sysd = main(["export-systemd", "--interface", "wg0"])
        self.assertEqual(rc_sysd, 0)


if __name__ == "__main__":
    unittest.main()
