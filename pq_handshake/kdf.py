#!/usr/bin/env python3
"""
kdf.py — Key Derivation Function using HMAC-BLAKE2b

Takes the raw 32-byte shared secret from ML-KEM-768 and derives
a proper 32-byte WireGuard PSK from it.

Why we do this instead of using the shared secret directly:
  1. Best practice — always run raw KEM output through a KDF
  2. Binds the key to this specific protocol via the context string
  3. Ensures uniform distribution regardless of KEM implementation
"""

import hmac
import hashlib
import base64


def derive_psk(
    shared_secret: bytes,
    context: bytes = b"pq-wireguard-v1"
) -> bytes:
    """
    Derive a 32-byte WireGuard PSK from the ML-KEM-768 shared secret.

    Uses HMAC-BLAKE2b:
      key     = shared_secret (32 bytes from ML-KEM-768)
      message = context string (binds this PSK to pq-wireguard only)
      hash    = BLAKE2b

    Returns exactly 32 bytes — the required size for a WireGuard PSK.
    """

    # hmac.new() creates an HMAC object
    # key=shared_secret : the raw KEM output is our HMAC key
    # msg=context       : protocol binding string
    # digestmod         : BLAKE2b as the underlying hash function
    h = hmac.new(
        key=shared_secret,
        msg=context,
        digestmod=hashlib.blake2b
    )

    # BLAKE2b default output is 64 bytes — we take only the first 32
    # WireGuard PSK must be exactly 32 bytes
    psk = h.digest()[:32]

    print(f"[KDF] Derived PSK via HMAC-BLAKE2b")
    print(f"[KDF] PSK (hex): {psk.hex()}")

    return psk


def psk_to_base64(psk: bytes) -> str:
    """
    Convert the 32-byte PSK to base64.
    WireGuard's wg command expects PSKs as base64 strings.
    """
    return base64.b64encode(psk).decode('utf-8')


if __name__ == "__main__":
    # Quick self-test when run directly
    import os

    # Generate a random 32-byte secret to simulate ML-KEM output
    fake_shared_secret = os.urandom(32)
    print(f"[test] Fake shared secret : {fake_shared_secret.hex()}")

    psk = derive_psk(fake_shared_secret)
    psk_b64 = psk_to_base64(psk)

    print(f"[test] PSK (hex)   : {psk.hex()}")
    print(f"[test] PSK (base64): {psk_b64}")
    print(f"[test] PSK length  : {len(psk)} bytes (must be 32)")
    assert len(psk) == 32, "PSK must be exactly 32 bytes"
    print(f"[test] PASS")
