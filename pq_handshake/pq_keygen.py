#!/usr/bin/env python3
"""
pq_keygen.py — Generate ML-KEM-768 keypair using liboqs.

Designed for operator-mediated provisioning:
  - Prints public key to stdout so operator can copy it to the peer
  - Saves full keypair locally for later decapsulation
  - Secret key NEVER leaves the container

Usage:
  python3 pq_keygen.py generate              → generates and saves keypair
  python3 pq_keygen.py show-public           → prints public key (to send to peer)
  python3 pq_keygen.py show-secret           → prints secret key (for decaps later)
"""

import json
import base64
import os
import sys
import oqs

KEYPAIR_PATH = "/peer_config/wg_keys/mlkem_keypair.json"
os.makedirs("/peer_config/wg_keys", exist_ok=True)


def generate_keypair() -> dict:
    """
    Generate a fresh ML-KEM-768 keypair and save it to disk.
    Prints a clean summary so the operator can copy the public key.
    """
    # oqs.KeyEncapsulation instantiates the liboqs C KEM object
    # "ML-KEM-768" is the NIST FIPS 203 final standardized name
    kem = oqs.KeyEncapsulation("ML-KEM-768")

    # generate_keypair() calls OQS_KEM_keypair() in C
    # Returns the public key bytes; secret key is held internally
    pk = kem.generate_keypair()

    # export_secret_key() extracts secret key from the C struct into Python bytes
    sk = kem.export_secret_key()

    keypair = {
        "algorithm":  "ML-KEM-768",
        "public_key": base64.b64encode(pk).decode('utf-8'),
        "secret_key": base64.b64encode(sk).decode('utf-8'),
    }

    # Save to disk — the secret key stays here, never printed
    with open(KEYPAIR_PATH, 'w') as f:
        json.dump(keypair, f, indent=2)

    # Free C-allocated memory — zeroes the secret key in memory
    kem.free()

    print(f"[keygen] ML-KEM-768 keypair generated")
    print(f"[keygen] pk={len(pk)}B  sk={len(sk)}B")
    print(f"[keygen] Saved to {KEYPAIR_PATH}")
    print(f"")
    print(f"PUBLIC KEY (copy this to operator):")
    print(f"{keypair['public_key']}")

    return keypair


def show_public() -> str:
    """Print just the public key — operator copies this to the other node."""
    with open(KEYPAIR_PATH, 'r') as f:
        data = json.load(f)
    # Print raw key with no decoration so it can be copy-pasted cleanly
    print(data["public_key"])
    return data["public_key"]


def show_secret() -> str:
    """Print the secret key — used when operator feeds it to decaps script."""
    with open(KEYPAIR_PATH, 'r') as f:
        data = json.load(f)
    print(data["secret_key"])
    return data["secret_key"]


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "generate"
    if cmd == "generate":
        generate_keypair()
    elif cmd == "show-public":
        show_public()
    elif cmd == "show-secret":
        show_secret()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
