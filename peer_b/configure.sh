#!/bin/bash
# configure.sh — Node B side
#
# Usage:
#   bash /peer_config/configure.sh \
#       <peer_a_wg_pubkey> \
#       <psk_base64> \
#       <peer_a_endpoint>   (e.g. 172.20.0.2:51820)

set -e

PEER_WG_PUB="$1"
PSK_B64="$2"
PEER_ENDPOINT="$3"

if [ -z "$PEER_WG_PUB" ] || [ -z "$PSK_B64" ] || [ -z "$PEER_ENDPOINT" ]; then
    echo "Usage: $0 <peer_wg_pubkey> <psk_b64> <peer_endpoint>"
    exit 1
fi

echo "=== Node B — WireGuard + ML-KEM-768 PSK Configuration ==="
echo ""

WG_KEYS_DIR="/peer_config/wg_keys"
mkdir -p "$WG_KEYS_DIR"

if [ -f "$WG_KEYS_DIR/wg_private.key" ]; then
    echo "[WG] Reusing existing WireGuard keypair"
    WG_PRIVATE=$(cat "$WG_KEYS_DIR/wg_private.key")
else
    echo "[WG] Generating WireGuard keypair..."
    WG_PRIVATE=$(wg genkey)
    echo "$WG_PRIVATE" > "$WG_KEYS_DIR/wg_private.key"
    chmod 600 "$WG_KEYS_DIR/wg_private.key"
fi

WG_PUBLIC=$(echo "$WG_PRIVATE" | wg pubkey)
echo "$WG_PUBLIC" > "$WG_KEYS_DIR/wg_public.key"

echo "[WG] Node B WireGuard public key: $WG_PUBLIC"
echo ""

if ip link show wg0 &>/dev/null; then
    ip link del wg0
fi

ip link add dev wg0 type wireguard

# Node B is 10.0.0.2 in the tunnel
ip addr add 10.0.0.2/24 dev wg0

echo "$WG_PRIVATE" | wg set wg0 private-key /dev/stdin listen-port 51820
ip link set up dev wg0

echo "[WG] wg0 up at 10.0.0.2/24, listening on UDP 51820"
echo ""

echo "[PSK] Injecting ML-KEM-768 derived PSK into WireGuard peer config..."

echo "$PSK_B64" | wg set wg0 \
    peer "$PEER_WG_PUB" \
    preshared-key /dev/stdin \
    endpoint "$PEER_ENDPOINT" \
    allowed-ips 10.0.0.1/32 \
    persistent-keepalive 25

echo "[PSK] PSK injected successfully"
echo ""

echo "=== Node B WireGuard Status ==="
wg show
echo ""
echo "=== Node B Configuration Complete ==="
echo "  Tunnel IP    : 10.0.0.2"
echo "  Peer (Node A): 10.0.0.1 via $PEER_ENDPOINT"
echo "  Encryption   : ChaCha20-Poly1305 + ML-KEM-768 PSK"
echo ""
echo "  Test with: ping 10.0.0.1"
