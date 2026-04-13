#!/bin/bash
# configure.sh — called by operator once all keys are known
#
# Usage:
#   bash /peer_config/configure.sh \
#       <peer_b_wg_pubkey> \
#       <psk_base64> \
#       <peer_b_endpoint>   (e.g. 172.20.0.3:51820)
#
# This script:
#   1. Generates Node A's WireGuard keypair (or reuses existing)
#   2. Creates wg0 interface at 10.0.0.1
#   3. Adds Node B as a peer WITH the Kyber-derived PSK
#   4. Prints Node A's WireGuard public key for the operator

set -e

PEER_WG_PUB="$1"    # Node B's WireGuard public key (operator provides)
PSK_B64="$2"         # Kyber-derived PSK in base64 (operator provides)
PEER_ENDPOINT="$3"   # Node B's IP:port (operator provides)

if [ -z "$PEER_WG_PUB" ] || [ -z "$PSK_B64" ] || [ -z "$PEER_ENDPOINT" ]; then
    echo "Usage: $0 <peer_wg_pubkey> <psk_b64> <peer_endpoint>"
    echo "Example: $0 'abc123==' 'xyz789==' '172.20.0.3:51820'"
    exit 1
fi

echo "=== Node A — WireGuard + ML-KEM-768 PSK Configuration ==="
echo ""

# --- Generate or reuse WireGuard keypair ---
WG_KEYS_DIR="/peer_config/wg_keys"
mkdir -p "$WG_KEYS_DIR"

if [ -f "$WG_KEYS_DIR/wg_private.key" ]; then
    echo "[WG] Reusing existing WireGuard keypair"
    WG_PRIVATE=$(cat "$WG_KEYS_DIR/wg_private.key")
else
    echo "[WG] Generating WireGuard keypair..."
    WG_PRIVATE=$(wg genkey)
    # Save private key to file so we can reuse across configure.sh calls
    echo "$WG_PRIVATE" > "$WG_KEYS_DIR/wg_private.key"
    chmod 600 "$WG_KEYS_DIR/wg_private.key"
fi

# Derive public key from private key
WG_PUBLIC=$(echo "$WG_PRIVATE" | wg pubkey)
echo "$WG_PUBLIC" > "$WG_KEYS_DIR/wg_public.key"

echo "[WG] Node A WireGuard public key: $WG_PUBLIC"
echo "[WG] (Give this to the operator to configure Node B)"
echo ""

# --- Create or recreate wg0 interface ---
if ip link show wg0 &>/dev/null; then
    echo "[WG] Removing existing wg0..."
    ip link del wg0
fi

# ip link add dev wg0 type wireguard
# Creates a virtual WireGuard network interface backed by the kernel module
ip link add dev wg0 type wireguard

# Assign this node's tunnel IP — Node A is 10.0.0.1 in the tunnel namespace
ip addr add 10.0.0.1/24 dev wg0

# Configure the interface: set private key + listen port
# Reading private key from stdin so it never appears in process list
echo "$WG_PRIVATE" | wg set wg0 private-key /dev/stdin listen-port 51820

# Activate the interface
ip link set up dev wg0

echo "[WG] wg0 up at 10.0.0.1/24, listening on UDP 51820"
echo ""

# --- Add Node B as a peer WITH the Kyber-derived PSK ---
# This is the single most important step:
#   preshared-key /dev/stdin  → reads the PSK from stdin (security: avoids ps exposure)
#   endpoint                  → where to reach Node B
#   allowed-ips               → which traffic routes through the tunnel
#   persistent-keepalive 25   → send keepalive every 25s to maintain NAT mappings
echo "[PSK] Injecting ML-KEM-768 derived PSK into WireGuard peer config..."

echo "$PSK_B64" | wg set wg0 \
    peer "$PEER_WG_PUB" \
    preshared-key /dev/stdin \
    endpoint "$PEER_ENDPOINT" \
    allowed-ips 10.0.0.2/32 \
    persistent-keepalive 25

echo "[PSK] PSK injected successfully"
echo ""

# --- Show final state ---
echo "=== Node A WireGuard Status ==="
wg show
echo ""
echo "=== Node A Configuration Complete ==="
echo "  Tunnel IP    : 10.0.0.1"
echo "  Peer (Node B): 10.0.0.2 via $PEER_ENDPOINT"
echo "  Encryption   : ChaCha20-Poly1305 + ML-KEM-768 PSK"
echo ""
echo "  Test with: ping 10.0.0.2"
