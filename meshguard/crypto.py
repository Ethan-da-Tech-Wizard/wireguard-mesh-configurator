"""
meshguard.crypto - Pure-Python RFC 7748 Curve25519 Keypair Engine & Validator.

This module provides zero-dependency cryptographic operations for WireGuard networks:
1. RFC 7748 X25519 scalar multiplication to derive Curve25519 public keys from private keys.
2. Cryptographically secure private key generation with standard Curve25519 bit-clamping.
3. WireGuard PresharedKey (PSK) generation for post-quantum resistance.
4. Base64 encoding/decoding validation for 32-byte cryptographic keys.

===============================================================================
THE MATHEMATICAL ARCHITECTURE OF WIREGUARD KEYS (RFC 7748 & RFC 7539):
===============================================================================
WireGuard utilizes the Noise Protocol Framework (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s).
Every node in the network is identified solely by its static 32-byte (256-bit)
Curve25519 public key.

1. The Curve:
   Curve25519 is a Montgomery curve defined over the prime field GF(2^255 - 19):
       y^2 = x^3 + 486662 * x^2 + x

2. Montgomery Ladder & X-Coordinate Only:
   Instead of computing full (x, y) coordinates on a Weierstrass curve, RFC 7748
   multiplication operates exclusively on the x-coordinate (u-coordinate).
   The Montgomery ladder computes scalar multiplication Q = k * P in a fixed
   sequence of additions and doublings, avoiding data-dependent branching.

3. Key Clamping (RFC 7748 Section 5):
   A raw 32-byte random string cannot be used directly as a Curve25519 scalar.
   It must undergo bit-clamping:
       k[0]  &= 248  (0b11111000): Clears the lowest 3 bits. This guarantees that
                                   the scalar is a multiple of 8 (the curve cofactor).
                                   This neutralizes small-subgroup attacks where an
                                   adversary supplies a low-order curve point to
                                   glean modular residues of the private key.
       k[31] &= 127  (0b01111111): Clears bit 255 to keep the scalar within field bounds.
       k[31] |= 64   (0b01000000): Sets bit 254 to ensure the scalar always has a fixed
                                   bit length (254 bits), preventing variable-length
                                   timing leaks in naive Montgomery ladder loops.

4. Base64 Representation:
   A 32-byte binary key is serialized for `wg` and `wg-quick` configuration files as
   a standard Base64 string of length 44 ending with an equals sign ('='):
       ceil(32 * 8 / 6) = 44 characters (32 bytes * 4/3 = 42.66 -> padded to 44).
"""

import base64
import os
import re
import secrets
from typing import Tuple

# -----------------------------------------------------------------------------
# RFC 7748 Field Arithmetic Constants
# -----------------------------------------------------------------------------
# Prime modulus: p = 2^255 - 19
# In hexadecimal: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
FIELD_PRIME: int = (1 << 255) - 19

# Montgomery curve constant: (A - 2) / 4 where A = 486662
# (486662 - 2) / 4 = 121665
A24: int = 121665

# Standard generator u-coordinate (base point) for Curve25519 (u = 9)
GENERATOR_U: int = 9

# Regex pattern for WireGuard base64 32-byte key: 43 base64 characters + '=' padding
KEY_B64_REGEX: re.Pattern = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def clamp_scalar(scalar_bytes: bytes) -> bytes:
    """
    Applies standard RFC 7748 bit clamping to a 32-byte scalar.

    Clamping forces the integer value of the scalar into a safe subspace:
    - Clears bits 0, 1, 2 to guarantee the scalar is a multiple of 8 (cofactor neutralization).
    - Clears bit 255.
    - Sets bit 254 to enforce uniform execution length in the Montgomery ladder.

    Args:
        scalar_bytes: 32 raw bytes of cryptographically random entropy.

    Returns:
        32 clamped bytes ready for Curve25519 scalar multiplication.

    Raises:
        ValueError: If input is not exactly 32 bytes in length.
    """
    if len(scalar_bytes) != 32:
        raise ValueError(f"Scalar must be exactly 32 bytes, received {len(scalar_bytes)} bytes.")

    # Convert immutable bytes into a mutable bytearray
    clamped = bytearray(scalar_bytes)

    # Clear lowest 3 bits: mask with 11111000 in binary (0xF8 or 248)
    clamped[0] &= 248

    # Clear bit 255: mask with 01111111 in binary (0x7F or 127)
    clamped[31] &= 127

    # Set bit 254: bitwise OR with 01000000 in binary (0x40 or 64)
    clamped[31] |= 64

    return bytes(clamped)


def _conditional_swap(swap: int, x_2: int, x_3: int) -> Tuple[int, int]:
    """
    Performs a conditional constant-time swap of two field coordinates.

    When swap == 1, returns (x_3, x_2).
    When swap == 0, returns (x_2, x_3).

    Uses field arithmetic to prevent conditional execution branches:
        dummy = swap * (x_2 - x_3)
        x_2 = x_2 - dummy
        x_3 = x_3 + dummy
    """
    dummy = (swap * (x_2 - x_3)) % FIELD_PRIME
    x_2 = (x_2 - dummy) % FIELD_PRIME
    x_3 = (x_3 + dummy) % FIELD_PRIME
    return x_2, x_3


def x25519_scalar_mult(scalar_bytes: bytes, u_coord: int = GENERATOR_U) -> bytes:
    """
    Performs RFC 7748 X25519 scalar multiplication Q = scalar * P.

    Implements the Montgomery ladder algorithm operating strictly on the u-coordinate.
    Computes Q = scalar * (u_coord) in the prime field GF(2^255 - 19).

    Args:
        scalar_bytes: 32-byte clamped scalar (private key).
        u_coord: Base point u-coordinate (default is 9 for the standard generator).

    Returns:
        32-byte little-endian encoded u-coordinate of the resulting public key.
    """
    # Parse scalar as a 256-bit little-endian integer
    k = int.from_bytes(scalar_bytes, byteorder="little")

    x_1 = u_coord
    x_2 = 1
    z_2 = 0
    x_3 = u_coord
    z_3 = 1
    swap = 0

    # Montgomery ladder: iterate over bits from bit 254 down to bit 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = _conditional_swap(swap, x_2, x_3)
        z_2, z_3 = _conditional_swap(swap, z_2, z_3)
        swap = k_t

        # Differential addition and doubling formulas for Montgomery curves
        a_val = (x_2 + z_2) % FIELD_PRIME
        aa_val = (a_val * a_val) % FIELD_PRIME
        b_val = (x_2 - z_2) % FIELD_PRIME
        bb_val = (b_val * b_val) % FIELD_PRIME
        e_val = (aa_val - bb_val) % FIELD_PRIME
        c_val = (x_3 + z_3) % FIELD_PRIME
        d_val = (x_3 - z_3) % FIELD_PRIME
        da_val = (d_val * a_val) % FIELD_PRIME
        cb_val = (c_val * b_val) % FIELD_PRIME

        x_3 = ((da_val + cb_val) ** 2) % FIELD_PRIME
        z_3 = (x_1 * ((da_val - cb_val) ** 2)) % FIELD_PRIME
        x_2 = (aa_val * bb_val) % FIELD_PRIME
        z_2 = (e_val * (aa_val + A24 * e_val)) % FIELD_PRIME

    # Final conditional swap to restore correct coordinate order
    x_2, x_3 = _conditional_swap(swap, x_2, x_3)
    z_2, z_3 = _conditional_swap(swap, z_2, z_3)

    # Invert z_2 modulo FIELD_PRIME using Fermat's Little Theorem:
    # z_2^(p - 1) = 1 (mod p) => z_2^(p - 2) = z_2^(-1) (mod p)
    z_2_inv = pow(z_2, FIELD_PRIME - 2, FIELD_PRIME)
    result_x = (x_2 * z_2_inv) % FIELD_PRIME

    # Serialize to 32 bytes little-endian per RFC 7748
    return result_x.to_bytes(32, byteorder="little")


def generate_private_key() -> str:
    """
    Generates a cryptographically secure 32-byte WireGuard private key.

    Draws 32 bytes of secure entropy from os.urandom (or secrets), applies
    RFC 7748 clamping, and encodes the result in Base64 with standard padding.

    Returns:
        Base64-encoded 44-character string representing the private key.
    """
    # 32 bytes (256 bits) of cryptographic entropy
    raw_entropy = secrets.token_bytes(32)
    # Clamp scalar to safe Curve25519 subgroup
    clamped = clamp_scalar(raw_entropy)
    # Encode to standard base64 string
    return base64.b64encode(clamped).decode("ascii")


def derive_public_key(private_key_b64: str) -> str:
    """
    Derives the corresponding 32-byte WireGuard public key from a Base64 private key.

    Decodes the Base64 private key, ensures it is clamped, executes X25519
    scalar multiplication against base point u=9, and returns the Base64 public key.

    Args:
        private_key_b64: 44-character Base64 string of the WireGuard private key.

    Returns:
        44-character Base64 string of the derived Curve25519 public key.

    Raises:
        ValueError: If the key format is invalid.
    """
    is_valid, err = validate_key_format(private_key_b64)
    if not is_valid:
        raise ValueError(f"Invalid private key: {err}")

    raw_priv = base64.b64decode(private_key_b64)
    # Apply clamping to ensure canonical scalar
    clamped_priv = clamp_scalar(raw_priv)
    # Calculate scalar multiplication: pub = priv * G
    pub_bytes = x25519_scalar_mult(clamped_priv, GENERATOR_U)
    return base64.b64encode(pub_bytes).decode("ascii")


def generate_keypair() -> Tuple[str, str]:
    """
    Generates a synchronized (private_key, public_key) pair in Base64 format.

    Returns:
        Tuple of (private_key_b64, public_key_b64).
    """
    priv = generate_private_key()
    pub = derive_public_key(priv)
    return priv, pub


def generate_preshared_key() -> str:
    """
    Generates a 32-byte cryptographically secure WireGuard PresharedKey (PSK).

    WireGuard supports an optional symmetric preshared key mixed into the Noise
    handshake (Noise_IKpsk2). If quantum computers eventually break Curve25519
    via Shor's algorithm, the symmetric 256-bit PSK ensures communications
    remain post-quantum secure against passive decryption.

    Returns:
        Base64-encoded 44-character string of 32 random bytes.
    """
    psk_bytes = secrets.token_bytes(32)
    return base64.b64encode(psk_bytes).decode("ascii")


def validate_key_format(key_str: str) -> Tuple[bool, str]:
    """
    Validates whether a string adheres to WireGuard's 32-byte Base64 key specification.

    Checks:
    1. String length (must be exactly 44 characters).
    2. Character set (Base64 characters followed by '=').
    3. Decoded byte length (must decode to exactly 32 bytes).
    4. Absence of obvious placeholder keys (e.g., all zeros, 'AAAA...', 'TODO').

    Args:
        key_str: Base64 candidate key string.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not isinstance(key_str, str):
        return False, f"Key must be a string, got {type(key_str).__name__}"

    stripped = key_str.strip()
    if len(stripped) != 44:
        return False, f"Key length is {len(stripped)} characters; WireGuard keys must be 44 characters."

    if not KEY_B64_REGEX.match(stripped):
        return False, "Key does not match Base64 pattern (43 alphanumeric/+/_ chars followed by '=')"

    try:
        raw = base64.b64decode(stripped, validate=True)
    except Exception as exc:
        return False, f"Base64 decoding failed: {exc}"

    if len(raw) != 32:
        return False, f"Decoded key is {len(raw)} bytes; must be exactly 32 bytes."

    # Check for suspicious null/placeholder keys
    if raw == b"\x00" * 32:
        return False, "Key is all zeros (placeholder/dummy key detected)"

    if stripped.startswith("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):
        return False, "Key is a trivial placeholder string ('AAA...')"

    return True, ""
