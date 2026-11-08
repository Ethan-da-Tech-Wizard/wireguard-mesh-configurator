"""
Program: WireGuard Mesh Configurator - Pure-Python RFC 7748 Curve25519 Engine
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Pure-Python RFC 7748 Curve25519 keypair generation, public key derivation via Montgomery ladder, bit-clamping, preshared key generation, and WireGuard key validation without external dependencies.
"""

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## Binary-to-ASCII encoding library for Base64 serialization of 32-byte keys
import base64
## Operating system interface for secure entropy access
import os
## Regular expression matching engine for format and character set validation
import re
## Cryptographically secure pseudo-random number generator (CSPRNG)
import secrets
## Type hinting annotations for tuple return types
from typing import Tuple

## ---------------------------------------------------------------------------
## RFC 7748 Field Arithmetic Constants
## ---------------------------------------------------------------------------
## Prime modulus p for Curve25519: p = 2^255 - 19
## In hexadecimal: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
FIELD_PRIME: int = (1 << 255) - 19

## Montgomery curve constant (A - 2) / 4 where A = 486662
## (486662 - 2) / 4 = 121665; used for point doubling in the Montgomery ladder
A24: int = 121665

## Standard generator u-coordinate (base point) for Curve25519 (u = 9)
GENERATOR_U: int = 9

## Regular expression pattern validating WireGuard Base64 key structure:
## Exactly 43 alphanumeric or '+' or '/' characters followed by '=' padding (44 chars total)
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
    ## Verify that the incoming byte buffer is exactly 32 bytes (256 bits)
    if len(scalar_bytes) != 32:
        raise ValueError(f"Scalar must be exactly 32 bytes, received {len(scalar_bytes)} bytes.")

    ## Convert immutable bytes into a mutable bytearray for in-place bitwise masking
    clamped = bytearray(scalar_bytes)

    ## Clear the lowest 3 bits of byte 0: mask with 0xF8 (11111000 in binary, or 248)
    ## This ensures the scalar is a multiple of 8, neutralizing small-subgroup attacks.
    clamped[0] &= 248

    ## Clear bit 255 (the most significant bit of byte 31): mask with 0x7F (01111111, or 127)
    ## Keeps the scalar strictly within the field size bound.
    clamped[31] &= 127

    ## Set bit 254 (second highest bit of byte 31): bitwise OR with 0x40 (01000000, or 64)
    ## Guarantees a constant bit-length of 254 bits, preventing timing leaks.
    clamped[31] |= 64

    ## Return the sanitized byte sequence as an immutable bytes object
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
    ## Compute difference scaled by the swap flag (0 or 1) in the prime field
    dummy = (swap * (x_2 - x_3)) % FIELD_PRIME

    ## If swap is 1, x_2 becomes x_2 - (x_2 - x_3) = x_3; if swap is 0, x_2 is unchanged
    x_2 = (x_2 - dummy) % FIELD_PRIME

    ## If swap is 1, x_3 becomes x_3 + (x_2 - x_3) = x_2; if swap is 0, x_3 is unchanged
    x_3 = (x_3 + dummy) % FIELD_PRIME

    ## Return the conditionally swapped coordinate pair
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
    ## Decode the 32-byte clamped scalar into a 256-bit little-endian integer
    k = int.from_bytes(scalar_bytes, byteorder="little")

    ## Initialize Montgomery ladder state variables in projective coordinates (X : Z)
    ## Point P: (x_1 : 1) where x_1 is the input base point u-coordinate
    x_1 = u_coord
    ## Accumulator point Q: initialized to point at infinity (1 : 0)
    x_2 = 1
    z_2 = 0
    ## Working point Q + P: initialized to base point (u : 1)
    x_3 = u_coord
    z_3 = 1
    ## Swap flag to maintain constant-time coordinate ordering
    swap = 0

    ## Loop over all 255 bits from bit 254 down to bit 0 (RFC 7748 Section 5)
    for t in reversed(range(255)):
        ## Extract the t-th bit of scalar k
        k_t = (k >> t) & 1

        ## Update swap flag and conditionally swap coordinates if bit changed
        swap ^= k_t
        x_2, x_3 = _conditional_swap(swap, x_2, x_3)
        z_2, z_3 = _conditional_swap(swap, z_2, z_3)
        swap = k_t

        ## Compute differential addition and point doubling on Montgomery curve
        ## a_val = x_2 + z_2
        a_val = (x_2 + z_2) % FIELD_PRIME
        ## aa_val = a_val^2
        aa_val = (a_val * a_val) % FIELD_PRIME
        ## b_val = x_2 - z_2
        b_val = (x_2 - z_2) % FIELD_PRIME
        ## bb_val = b_val^2
        bb_val = (b_val * b_val) % FIELD_PRIME
        ## e_val = aa_val - bb_val
        e_val = (aa_val - bb_val) % FIELD_PRIME
        ## c_val = x_3 + z_3
        c_val = (x_3 + z_3) % FIELD_PRIME
        ## d_val = x_3 - z_3
        d_val = (x_3 - z_3) % FIELD_PRIME
        ## da_val = d_val * a_val
        da_val = (d_val * a_val) % FIELD_PRIME
        ## cb_val = c_val * b_val
        cb_val = (c_val * b_val) % FIELD_PRIME

        ## Compute new coordinates for working point (Q + P)
        x_3 = ((da_val + cb_val) ** 2) % FIELD_PRIME
        z_3 = (x_1 * ((da_val - cb_val) ** 2)) % FIELD_PRIME
        ## Compute new coordinates for doubled point (2Q)
        x_2 = (aa_val * bb_val) % FIELD_PRIME
        z_2 = (e_val * (aa_val + A24 * e_val)) % FIELD_PRIME

    ## Perform final swap to place final result coordinates into (x_2, z_2)
    x_2, x_3 = _conditional_swap(swap, x_2, x_3)
    z_2, z_3 = _conditional_swap(swap, z_2, z_3)

    ## Compute modular multiplicative inverse of z_2 modulo p using Fermat's Little Theorem:
    ## Since p is prime, z_2^(p - 1) = 1 (mod p), so z_2^(p - 2) = z_2^(-1) (mod p).
    z_2_inv = pow(z_2, FIELD_PRIME - 2, FIELD_PRIME)

    ## Convert projective coordinate (x_2 : z_2) back to affine u-coordinate: u = x_2 * z_2^(-1)
    result_x = (x_2 * z_2_inv) % FIELD_PRIME

    ## Serialize the 256-bit integer into 32 little-endian bytes per RFC 7748 specification
    return result_x.to_bytes(32, byteorder="little")


def generate_private_key() -> str:
    """
    Generates a cryptographically secure 32-byte WireGuard private key.

    Draws 32 bytes of secure entropy from os.urandom (or secrets), applies
    RFC 7748 clamping, and encodes the result in Base64 with standard padding.

    Returns:
        Base64-encoded 44-character string representing the private key.
    """
    ## Gather 32 bytes (256 bits) of cryptographically secure random entropy
    raw_entropy = secrets.token_bytes(32)

    ## Enforce RFC 7748 bit clamping on the random scalar
    clamped = clamp_scalar(raw_entropy)

    ## Encode the 32 clamped bytes into a standard 44-character Base64 string
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
    ## Validate that the incoming private key matches WireGuard length and character rules
    is_valid, err = validate_key_format(private_key_b64)
    if not is_valid:
        raise ValueError(f"Invalid private key: {err}")

    ## Decode Base64 string into raw 32 binary bytes
    raw_priv = base64.b64decode(private_key_b64)

    ## Apply RFC 7748 clamping to ensure canonical Curve25519 scalar properties
    clamped_priv = clamp_scalar(raw_priv)

    ## Perform scalar multiplication against Curve25519 base point (u = 9)
    pub_bytes = x25519_scalar_mult(clamped_priv, GENERATOR_U)

    ## Encode public key bytes into standard 44-character Base64 representation
    return base64.b64encode(pub_bytes).decode("ascii")


def generate_keypair() -> Tuple[str, str]:
    """
    Generates a synchronized (private_key, public_key) pair in Base64 format.

    Returns:
        Tuple of (private_key_b64, public_key_b64).
    """
    ## Generate clamped random private key
    priv = generate_private_key()

    ## Compute corresponding Curve25519 public key
    pub = derive_public_key(priv)

    ## Return both keys as a paired tuple
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
    ## Gather 32 bytes of secure random symmetric key material
    psk_bytes = secrets.token_bytes(32)

    ## Encode symmetric key material to Base64 format
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
    ## Guard against non-string input types
    if not isinstance(key_str, str):
        return False, f"Key must be a string, got {type(key_str).__name__}"

    ## Remove leading/trailing whitespace
    stripped = key_str.strip()

    ## WireGuard keys must be exactly 44 characters long
    if len(stripped) != 44:
        return False, f"Key length is {len(stripped)} characters; WireGuard keys must be 44 characters."

    ## Validate character set against standard Base64 pattern ending with '='
    if not KEY_B64_REGEX.match(stripped):
        return False, "Key does not match Base64 pattern (43 alphanumeric/+/_ chars followed by '=')"

    ## Attempt to decode Base64 string to verify padding and binary integrity
    try:
        raw = base64.b64decode(stripped, validate=True)
    except Exception as exc:
        return False, f"Base64 decoding failed: {exc}"

    ## WireGuard Curve25519 keys must decode to exactly 32 binary bytes
    if len(raw) != 32:
        return False, f"Decoded key is {len(raw)} bytes; must be exactly 32 bytes."

    ## Detect trivial placeholder key consisting of 32 zero bytes
    if raw == b"\x00" * 32:
        return False, "Key is all zeros (placeholder/dummy key detected)"

    ## Detect trivial unconfigured placeholder string consisting of repeated 'A's
    if stripped.startswith("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):
        return False, "Key is a trivial placeholder string ('AAA...')"

    ## Key satisfies all syntactic and structural invariants
    return True, ""
