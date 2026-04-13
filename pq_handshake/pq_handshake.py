#!/usr/bin/env python3
"""
pq_handshake.py — Operator-side ML-KEM-768 encapsulation and decapsulation.

In the real-world model, the OPERATOR (not the nodes themselves) runs
encapsulation using the responder's public key. This produces:
  - A shared_secret  (stays with operator, used to derive PSK for Node A)
  - A ciphertext     (sent to Node B, which decapsulates to get same secret)

Usage:
  # Operator encapsulates using Node B's public key:
  python3 pq_handshake.py encapsulate <peer_b_mlkem_pubkey_b64>

  # Node B decapsulates using its secret key and the ciphertext:
  python3 pq_handshake.py decapsulate <secret_key_b64> <ciphertext_b64>

Both commands print the derived PSK in base64 — ready to inject into WireGuard.
"""

import base64
import sys
import oqs

from kdf import derive_psk, psk_to_base64


def encapsulate(peer_public_key_b64: str) -> dict:
    """
    Encapsulate a shared secret using the peer's ML-KEM-768 public key.

    Takes the peer's public key as a base64 string (copy-pasted by operator).
    Returns a dict with ciphertext_b64 and psk_b64.

    The operator:
      1. Gives psk_b64 to Node A  → injected as WireGuard PSK
      2. Gives ciphertext_b64 to Node B → Node B decapsulates to get same PSK
    """
    # Decode the base64 public key back to raw bytes
    # This is what the operator copy-pasted from Node B's keygen output
    peer_pk = base64.b64decode(peer_public_key_b64.strip())

    print(f"[encaps] Peer public key loaded: {len(peer_pk)} bytes")
    print(f"[encaps] Running ML-KEM-768 encapsulation via liboqs...")

    # Create a KEM object purely for encapsulation — no keypair generation needed
    kem = oqs.KeyEncapsulation("ML-KEM-768")

    # encap_secret(pk) calls OQS_KEM_encaps() in C:
    #   → generates a random 32-byte shared_secret internally
    #   → encrypts it under peer_pk → produces 1088-byte ciphertext
    #   → returns (ciphertext_bytes, shared_secret_bytes)
    ciphertext, shared_secret = kem.encap_secret(peer_pk)

    print(f"[encaps] Ciphertext   : {len(ciphertext)} bytes")
    print(f"[encaps] Shared secret: {len(shared_secret)} bytes")
    print(f"[encaps] Shared secret (hex): {shared_secret.hex()}")

    # Derive the 32-byte WireGuard PSK from the shared secret
    # HMAC-BLAKE2b ensures uniform distribution and protocol binding
    psk = derive_psk(shared_secret)
    psk_b64 = psk_to_base64(psk)

    kem.free()

    print(f"")
    print(f"=" * 60)
    print(f"CIPHERTEXT (send this to Node B):")
    print(f"{base64.b64encode(ciphertext).decode('utf-8')}")
    print(f"")
    print(f"PSK for Node A (inject into WireGuard):")
    print(f"{psk_b64}")
    print(f"=" * 60)

    return {
        "ciphertext_b64":   base64.b64encode(ciphertext).decode('utf-8'),
        "shared_secret_hex": shared_secret.hex(),
        "psk_b64":          psk_b64,
    }


def decapsulate(ciphertext_b64: str) -> str:
    """
    Decapsulate using our secret key read directly from disk.
    Secret key is never passed as a shell argument — avoids base64
    corruption from shell variable expansion.
    """
    # Read secret key directly from the keypair file on disk
    # This is safer than passing it as a shell argument
    KEYPAIR_PATH = "/peer_config/wg_keys/mlkem_keypair.json"

    import json
    with open(KEYPAIR_PATH, 'r') as f:
        keypair = json.load(f)

    sk_bytes = base64.b64decode(keypair["secret_key"])
    ciphertext = base64.b64decode(ciphertext_b64.strip())

    print(f"[decaps] Secret key loaded from disk: {len(sk_bytes)} bytes")
    print(f"[decaps] Ciphertext loaded: {len(ciphertext)} bytes")
    print(f"[decaps] Running ML-KEM-768 decapsulation via liboqs...")

    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=sk_bytes)
    shared_secret = kem.decap_secret(ciphertext)

    print(f"[decaps] Shared secret: {len(shared_secret)} bytes")
    print(f"[decaps] Shared secret (hex): {shared_secret.hex()}")

    psk = derive_psk(shared_secret)
    psk_b64 = psk_to_base64(psk)

    kem.free()

    print(f"")
    print(f"=" * 60)
    print(f"PSK for Node B (inject into WireGuard):")
    print(f"{psk_b64}")
    print(f"=" * 60)

    return psk_b64


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "encapsulate":
        # sys.argv[2] is the peer's ML-KEM public key in base64
        result = encapsulate(sys.argv[2])

    elif mode == "decapsulate":
        # Only ciphertext is passed as argument
        # Secret key is read from disk inside the function
        psk_b64 = decapsulate(sys.argv[2])

    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
