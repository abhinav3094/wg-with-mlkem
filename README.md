# wg-with-mlkem
Implementation of Post Quantum Cryptography Liboqs ML-KEM 768 with Wireguard tunneling Protocol. This version uses Docker containers to demonstrate a successful WireGuard tunnel handshake with PQC PSK.

# ── STEP 0: Start containers (they just sleep, nothing auto-runs) ──────────
docker-compose up -d --build

# ── STEP 1: Generate ML-KEM-768 keypairs on both nodes ────────────────────

# Node A generates its ML-KEM keypair
docker exec peer_a python3 /pq_handshake/pq_keygen.py generate
# → prints Node A's ML-KEM public key — copy it (we'll call it MLKEM_PUB_A)

# Node B generates its ML-KEM keypair
docker exec peer_b python3 /pq_handshake/pq_keygen.py generate
# → prints Node B's ML-KEM public key — copy it (we'll call it MLKEM_PUB_B)

# ── STEP 2: Generate WireGuard keypairs on both nodes ─────────────────────
# We call configure.sh with dummy args just to trigger WG key generation,
# OR we add a dedicated keygen step. Cleanest: generate WG keys explicitly.

docker exec peer_a bash -c "
    mkdir -p /peer_config/wg_keys
    wg genkey | tee /peer_config/wg_keys/wg_private.key | wg pubkey > /peer_config/wg_keys/wg_public.key
    echo 'Node A WG public key:'
    cat /peer_config/wg_keys/wg_public.key
"
# → copy Node A's WG public key (WG_PUB_A)

docker exec peer_b bash -c "
    mkdir -p /peer_config/wg_keys
    wg genkey | tee /peer_config/wg_keys/wg_private.key | wg pubkey > /peer_config/wg_keys/wg_public.key
    echo 'Node B WG public key:'
    cat /peer_config/wg_keys/wg_public.key
"
# → copy Node B's WG public key (WG_PUB_B)

# ── STEP 3: Operator runs ML-KEM encapsulation using Node B's public key ──
# You do this locally — no container needed, just Python + liboqs installed
# OR run it inside one of the containers (doesn't matter — no secret key here)

MLKEM_PUB_B="<paste Node B's ML-KEM public key here>"

docker exec peer_a python3 /pq_handshake/pq_handshake.py encapsulate "$MLKEM_PUB_B"
# → prints two things — copy both:
#     CIPHERTEXT  (send to Node B)
#     PSK for Node A  (inject into Node A)

# ── STEP 4: Node B decapsulates using its secret key ──────────────────────
# Node B's secret key never left Node B — we retrieve it from its keypair file

SK_B=$(docker exec peer_b python3 /pq_handshake/pq_keygen.py show-secret)
CIPHERTEXT="<paste ciphertext from step 3>"

docker exec peer_b python3 /pq_handshake/pq_handshake.py decapsulate "$SK_B" "$CIPHERTEXT"
Updated: docker exec peer_b python3 /pq_handshake/pq_handshake.py decapsulate "$CIPHERTEXT"
# → prints PSK for Node B — must be IDENTICAL to PSK from step 3

# ── STEP 5: Configure both WireGuard interfaces with PSK ──────────────────

WG_PUB_A="<paste from step 2>"
WG_PUB_B="<paste from step 2>"
PSK_A="<paste from step 3>"    # same value as PSK_B
PSK_B="<paste from step 4>"    # verify it matches PSK_A!

docker exec peer_a bash /peer_config/configure.sh "$WG_PUB_B" "$PSK_A" "172.21.0.3:51820"
docker exec peer_b bash /peer_config/configure.sh "$WG_PUB_A" "$PSK_B" "172.21.0.2:51820"

# ── STEP 6: Test the tunnel ────────────────────────────────────────────────
docker exec peer_a ping -c 4 10.0.0.2
docker exec peer_b ping -c 4 10.0.0.1

# ── STEP 7: Verify PSK is active on both sides ────────────────────────────
docker exec peer_a wg show
docker exec peer_b wg show
# Both must show:  preshared key: (hidden)
