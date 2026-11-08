# MeshGuard (WireGuard Mesh Configurator & Audit Engine)

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(pure%20stdlib)-success.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 100% Passing](https://img.shields.io/badge/tests-22%2F22%20passing-brightgreen.svg)](tests/test_meshguard.py)
[![Protocol: WireGuard](https://img.shields.io/badge/protocol-WireGuard%20(Noise__IKpsk2)-red.svg)](https://www.wireguard.com/)

> **A zero-dependency, pure-Python 3 standard-library WireGuard mesh configuration synthesizer, topology visualizer, and cryptokey collision audit engine.**
> Built for sysadmins, DevOps engineers, and homelabbers deploying resilient, peer-to-peer overlay networks across Linux, macOS, and BSD without SaaS dependencies or heavyweight cloud overlays.

```
       ╔════════════════════════════════════════════════════════════╗
       ║                  WIREGUARD MESH TOPOLOGY                   ║
       ╚════════════════════════════════════════════════════════════╝
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
  │  GATEWAY-01  │◄═══════►│  GATEWAY-02  │◄═══════►│  GATEWAY-03  │
  │ 10.100.0.1   │ (Direct │ 10.100.0.2   │ (Direct │ 10.100.0.3   │
  │ Pub: 4Xv9... │   UDP)  │ Pub: 9Lm2... │   UDP)  │ Pub: 7Kp1... │
  └──────────────┘         └──────────────┘         └──────────────┘
         ▲                                                 ▲
         │                                                 │
         └══════════════ (Direct P2P UDP) ═════════════════┘
```

---

## ⚡ The Problem: The $O(N^2)$ Edge Trap of Manual WireGuard

WireGuard is the fastest, leanest VPN protocol in existence, but it is intentionally unopinionated. It lacks a dynamic routing daemon or control plane.

When scaling a WireGuard network beyond two endpoints:
1. **Combinatorial Configuration Overhead**: A full-mesh network of $N$ nodes requires $\frac{N(N - 1)}{2}$ unique peering relationships. A 10-node mesh demands **45 synchronized peering declarations** across 10 individual configuration files.
2. **Cryptokey Routing Collisions**: WireGuard routes outbound packets by matching the destination IP against an internal Radix trie built from `AllowedIPs`. If two peers on the same interface have overlapping subnets (e.g., Peer A has `10.100.0.0/24` and Peer B has `10.100.0.5/32`), **WireGuard will silently drop or hijack packets**.
3. **Subnet Mask Misapplication**: Assigning `10.100.0.0/24` in a remote peer's `AllowedIPs` instead of `/32` causes that single peer to steal all mesh traffic, blackholing every other node.
4. **Silent NAT Expirations**: When endpoints sit behind NAT or CGNAT without a static public IP, stateful firewall state tables expire after 30–120 seconds of silence, severing inbound connectivity unless periodic keepalives (`PersistentKeepalive = 25`) are applied.
5. **Path MTU (PMTU) Blackholes**: Setting `MTU = 1500` ignores the 60-byte (IPv4) or 80-byte (IPv6) encapsulation overhead. Encapsulated UDP packets exceed standard 1500-byte MTU, causing fragmentation drops and dropped TLS handshakes across intermediate ISPs.

**MeshGuard completely automates this lifecycle.** It synthesizes synchronized configurations, audits subnets for collisions, verifies MTU bounds, derives Curve25519 public keys in pure Python, renders ASCII topology matrices, and outputs production systemd services.

---

## 🚀 Key Features

* **Zero Dependencies**: Pure Python 3 standard library (`ipaddress`, `base64`, `secrets`, `pathlib`, `argparse`, `dataclasses`). Runs instantly on any minimal Linux server, Raspberry Pi, macOS laptop, or BSD box.
* **Dual Topology Synthesizer**:
  * **Full Mesh**: Every node peers directly with every other node for minimum latency ($O(1)$ hops) and zero single points of failure.
  * **Hub-and-Spoke**: Central relay hubs route traffic between private spokes behind NAT/firewalls.
* **Cryptokey Routing Radix Trie Auditor**: Mathematically verifies that all `AllowedIPs` across all interfaces are disjoint, preventing route hijacking and packet drops.
* **Pure Python RFC 7748 X25519 Engine**: Computes Montgomery curve scalar multiplication in standard Python. Generates private keys, bit-clamps scalars, and derives public keys matching kernel `wg pubkey` without external tools or binaries.
* **NAT Boundary Awareness**: Automatically detects whether nodes possess public endpoints and injects `PersistentKeepalive = 25` for peers traversal.
* **PMTU & Encapsulation Analyzer**: Warns against MTU 1500 fragmentation hazards and enforces the RFC 8200 IPv6 1280-byte minimum.
* **Terminal ASCII Visualizer**: Renders interactive topology diagrams, node inventories, and $N \times N$ longest-prefix routing matrices directly in stdout.
* **Production Linux Integration**: Generates hardened `wg-quick@wg0.service` systemd units and native `systemd-networkd` (`.netdev` and `.network`) configurations.

---

## 📦 Installation

Since MeshGuard has **zero pip dependencies**, you can run it directly with any Python 3.8+ interpreter or install it into your local environment:

```bash
# Clone the repository
git clone https://github.com/Ethan-da-Tech-Wizard/wireguard-mesh-configurator.git
cd wireguard-mesh-configurator

# Test immediately
python3 -m unittest discover -s tests -v

# (Optional) Install locally as a CLI tool
pip install .
```

---

## 🛠️ CLI Quick Start

### 1. Initialize a Mesh Blueprint
Generate a starter JSON blueprint with freshly generated Curve25519 keys:
```bash
python3 -m meshguard init --topology full_mesh --nodes 3 --output mesh.json
```

### 2. Visualize Network Topology & Routing Matrix
Inspect the connectivity graph and routing paths in your terminal:
```bash
python3 -m meshguard visualize --config mesh.json
```
Output:
```
======================================================================
=============== WIREGUARD MESH TOPOLOGY: HOMELAB-MESH ================
              Topology Model: FULL_MESH | Total Nodes: 3              
======================================================================

NODE INVENTORY & IP ALLOCATION TABLE
──────────────────────────────────────────────────────────────────────
Node Name        Overlay IP         Endpoint               Role
──────────────────────────────────────────────────────────────────────
node-01          10.100.0.1/24      vpn.example.com:51820  Spoke (Peer)
node-02          10.100.0.2/24      vpn.example.com:51821  Spoke (Peer)
node-03          10.100.0.3/24      [NAT / Dynamic]        Spoke (Peer)
──────────────────────────────────────────────────────────────────────

CONNECTIVITY DIAGRAM
──────────────────────────────────────────────────────────────────────
FULL-MESH TOPOLOGY (Decentralized Direct P2P):

  [1] node-01 (10.100.0.1/24) @ vpn.example.com:51820
  [2] node-02 (10.100.0.2/24) @ vpn.example.com:51821
  [3] node-03 (10.100.0.3/24) [Behind NAT]

  Interconnection Graph:
    node-01        ◄══════ (Direct P2P Encrypted UDP) ══════► node-02
    node-01        ◄══════ (Direct P2P Encrypted UDP) ══════► node-03
    node-02        ◄══════ (Direct P2P Encrypted UDP) ══════► node-03

ROUTING PATH MATRIX (Longest-Prefix Cryptokey Mapping)
──────────────────────────────────────────────────────────────────────
Source / Dest   node-01         node-02         node-03         
────────────────────────────────────────────────────────────────
node-01         [SELF]          DIRECT P2P      DIRECT P2P      
node-02         DIRECT P2P      [SELF]          DIRECT P2P      
node-03         DIRECT P2P      DIRECT P2P      [SELF]          
────────────────────────────────────────────────────────────────
```

### 3. Synthesize Synchronized Configurations
Compile the blueprint into deployment-ready `wg0.conf` files, systemd services, and `systemd-networkd` definitions:
```bash
python3 -m meshguard generate --config mesh.json --output-dir ./output --interface wg0
```
This produces:
```
output/
├── node-01/
│   ├── wg0.conf               # Chmod 0600 wg-quick config
│   ├── wg-quick@wg0.service   # Hardened systemd unit
│   └── systemd-networkd/
│       ├── wg0.netdev         # WireGuard virtual device definition
│       └── wg0.network        # Address & routing rule mapping
├── node-02/
│   └── ...
└── node-03/
    └── ...
```

### 4. Audit Existing Configurations or Blueprints
Run the audit engine to verify IP uniqueness, AllowedIPs collision avoidance, and MTU boundaries:
```bash
python3 -m meshguard audit --dir ./output
```
Clean output:
```
✓ All audit checks passed! No subnet collisions, key faults, or MTU anomalies detected.
```

If a collision is detected (e.g., two peers claim overlapping subnets):
```
======================================================================
 AUDIT FINDINGS (1 issues found)
 CRITICAL: 1 | ERROR: 0 | WARNING: 0 | INFO: 0
======================================================================
[CRITICAL] COLLISION-001: Peer AllowedIPs Overlap Collision
  Target: /etc/wireguard/wg0.conf
  Detail: AllowedIPs collision detected on interface! Peer 'node-02' claims
          '10.100.0.0/24' which overlaps with '10.100.0.5/32' claimed by 'node-03'.
          WireGuard cryptokey routing cannot disambiguate this route and will
          silently drop or hijack packets.
  Action: Ensure AllowedIPs entries across peers on the same interface are mutually exclusive.
----------------------------------------------------------------------
```

### 5. Generate Keys & Derive Public Keys in Pure Python
Generate standard 32-byte Base64 WireGuard keypairs or derive public keys without `wg`:
```bash
# Generate fresh Curve25519 keypair
python3 -m meshguard keygen

# Generate Post-Quantum PresharedKey (PSK)
python3 -m meshguard keygen --psk

# Derive public key from an existing private key
python3 -m meshguard keygen --derive-public "yAnCLwgEgqAn0j5V45smAU2S48n7QkS/e9jX+V3WzH0="
```

---

## 🔬 Protocol & Networking Deep Dive

### 1. WireGuard MTU Calculation & Header Overhead

Why does MeshGuard default to an MTU of **1420 bytes** instead of the standard Ethernet MTU of 1500?

WireGuard operates in user-space or kernel-space by encapsulating standard inner IP packets inside outer UDP datagrams.

| Layer | Protocol | Header Size (IPv4 Outer) | Header Size (IPv6 Outer) |
|---|---|---|---|
| **Outer Network** | IPv4 or IPv6 Header | 20 bytes | 40 bytes |
| **Outer Transport** | UDP Header | 8 bytes | 8 bytes |
| **Encapsulation** | WireGuard Type + Receiver + Counter | 16 bytes | 16 bytes |
| **Authentication** | Poly1305 Message Authentication Code (MAC) | 16 bytes | 16 bytes |
| **Total Overhead** | | **60 bytes** | **80 bytes** |

$$\text{Usable IPv4 MTU} = 1500 - 60 = 1440 \text{ bytes}$$
$$\text{Usable IPv6 MTU} = 1500 - 80 = 1420 \text{ bytes}$$

If a network interface uses PPPoE (common with DSL and fiber ONT handoffs), an additional 8 bytes of PPPoE framing overhead is consumed:
$$\text{PPPoE IPv6 MTU} = 1500 - 80 - 8 = 1412 \text{ bytes}$$

**The Fragmentation Trap**: If `MTU = 1500` is configured on `wg0`, packets with 1500 bytes of inner payload expand to 1560 or 1580 bytes. If upstream routers or firewalls drop ICMP Type 3, Code 4 (*Destination Unreachable: Fragmentation Needed*), Path MTU Discovery (PMTUD) fails, creating a **Path MTU blackhole**. SSH connections will hang upon running commands with large output, and TLS handshakes will time out. MeshGuard enforces a default MTU of 1420 to guarantee fragmentation-free transit across both IPv4 and IPv6 backbones.

---

### 2. RFC 7748 Curve25519 Scalar Clamping

MeshGuard embeds a pure-Python Montgomery ladder scalar multiplication routine. In Curve25519, private keys are 32 bytes (256 bits) of entropy that must be bit-clamped:

```python
def clamp_scalar(scalar_bytes: bytes) -> bytes:
    clamped = bytearray(scalar_bytes)
    clamped[0]  &= 248  # 0b11111000: Clear lowest 3 bits
    clamped[31] &= 127  # 0b01111111: Clear bit 255
    clamped[31] |= 64   # 0b01000000: Set bit 254
    return bytes(clamped)
```

* **Clearing bits 0, 1, 2**: Multiplies the scalar by 8 (the cofactor of Curve25519). This neutralizes small-subgroup attacks where an adversary supplies an invalid curve point of order 2, 4, or 8 to leak modular residues of the private key.
* **Clearing bit 255**: Ensures the scalar integer remains strictly within the field size bound $2^{255} - 19$.
* **Setting bit 254**: Enforces a constant execution length for the Montgomery ladder, eliminating data-dependent timing side channels.

---

### 3. Cryptokey Routing & The Radix Trie Invariant

WireGuard dispenses with virtual IP addresses and dynamic tunnel state machines. Instead, it enforces **Cryptokey Routing**:
* **Outbound**: The kernel performs a longest-prefix match on the inner packet's destination IP against the peer's `AllowedIPs` Radix trie. The packet is encrypted with the associated public key and transmitted to the remote UDP endpoint.
* **Inbound**: The packet is decrypted with the local private key. The kernel checks whether the decrypted packet's *inner source IP* falls within the sender's `AllowedIPs`. If not, **the packet is dropped immediately**.

Because each IP address must map deterministically to exactly one public key, **no two peers on the same interface can possess overlapping `AllowedIPs`**. MeshGuard's audit engine validates this invariant using interval tree intersection algorithms.

---

## 🎯 Technical Interview Defense & Architectural Q&A

**Q: Why build this with zero dependencies instead of using Click, Jinja2, or PyRoute2?**
> **A:** Infrastructure automation tools should be resilient and run in minimal, air-gapped recovery environments. Standard library Python is ubiquitous across Linux recovery images, minimal container images (`python:slim`), and embedded routers. Introducing dependencies creates supply-chain risk and installation hurdles on air-gapped Bastion hosts.

**Q: How does MeshGuard prevent split-brain routes when nodes have multiple local subnets?**
> **A:** When generating full-mesh or hub-and-spoke configurations, MeshGuard isolates overlay addresses to `/32` (IPv4) and `/128` (IPv6) single-host prefixes in remote peers' `AllowedIPs`. Advertised LAN subnets (`extra_allowed_ips`) are audited against the global mesh IP space to guarantee that no local subnet collides with an assigned overlay address.

**Q: How does MeshGuard handle dynamic IP addresses and mobile clients?**
> **A:** WireGuard features automatic endpoint roaming: whenever an authenticated packet arrives from a peer, WireGuard updates that peer's endpoint to the packet's source IP and port. For clients behind NAT, MeshGuard omits the `Endpoint` parameter in remote peers and automatically injects `PersistentKeepalive = 25` on the client, ensuring outbound NAT states stay active.

---

## 🧪 Test Suite Execution

MeshGuard includes a comprehensive unit test suite covering key derivation, bit clamping, subnet collisions, MTU boundaries, configuration parsing, and CLI commands:

```bash
# Run test suite
python3 -m unittest discover -s tests -v
```

Expected output:
```
test_allowed_ips_collision_on_interface (test_meshguard.TestAuditor) ... ok
test_duplicate_mesh_ip_allocation (test_meshguard.TestAuditor) ... ok
test_endpoint_and_port_auditing (test_meshguard.TestAuditor) ... ok
test_file_permission_audit (test_meshguard.TestAuditor) ... ok
test_key_mismatch_detection (test_meshguard.TestAuditor) ... ok
test_mtu_boundaries (test_meshguard.TestAuditor) ... ok
test_parse_wg_conf (test_meshguard.TestAuditor) ... ok
test_cli_export_systemd (test_meshguard.TestCLI) ... ok
test_cli_init_and_generate_and_audit (test_meshguard.TestCLI) ... ok
test_cli_keygen (test_meshguard.TestCLI) ... ok
test_bit_clamping (test_meshguard.TestCrypto) ... ok
test_keypair_generation_and_derivation (test_meshguard.TestCrypto) ... ok
test_preshared_key (test_meshguard.TestCrypto) ... ok
test_rfc7748_alice_vector (test_meshguard.TestCrypto) ... ok
test_validate_key_format_invalid_inputs (test_meshguard.TestCrypto) ... ok
test_export_configs (test_meshguard.TestGenerator) ... ok
test_full_mesh_generation (test_meshguard.TestGenerator) ... ok
test_hub_and_spoke_generation (test_meshguard.TestGenerator) ... ok
test_node_routable_ips (test_meshguard.TestModels) ... ok
test_systemd_networkd_generation (test_meshguard.TestModels) ... ok
test_wg_quick_block_serialization (test_meshguard.TestModels) ... ok
test_render_all (test_meshguard.TestVisualizer) ... ok

----------------------------------------------------------------------
Ran 22 tests in 0.043s

OK
```

---

## 📄 License

MIT License. Designed and engineered by **Ethan Kilmer** (ethan@twu.software).
Contributions and issues welcome on [GitHub](https://github.com/Ethan-da-Tech-Wizard/wireguard-mesh-configurator).
