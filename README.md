# Overview

Implementation of Post Quantum Cryptography Liboqs ML-KEM 768 with Wireguard tunneling Protocol. This version uses Docker containers to demonstrate a successful WireGuard tunnel handshake with PQC PSK.

---

## Step 0 — Start Containers

They just sleep; nothing auto-runs.

```bash
docker-compose up -d --build
```

---

## Step 1 — Generate ML-KEM-768 Keypairs on Both Nodes

**Node A** generates its ML-KEM keypair:
```bash
docker exec peer_a python3 /pq_handshake/pq_keygen.py generate
# → prints Node A's ML-KEM public key — copy it (we'll call it MLKEM_PUB_A)
```

**Node B** generates its ML-KEM keypair:
```bash
docker exec peer_b python3 /pq_handshake/pq_keygen.py generate
# → prints Node B's ML-KEM public key — copy it (we'll call it MLKEM_PUB_B)
```

---

## Step 2 — Generate WireGuard Keypairs on Both Nodes

We call `configure.sh` with dummy args just to trigger WG key generation,
OR we add a dedicated keygen step. Cleanest: generate WG keys explicitly.

**Node A:**
```bash
docker exec peer_a bash -c "
    mkdir -p /peer_config/wg_keys
    wg genkey | tee /peer_config/wg_keys/wg_private.key | wg pubkey > /peer_config/wg_keys/wg_public.key
    echo 'Node A WG public key:'
    cat /peer_config/wg_keys/wg_public.key
"
# → copy Node A's WG public key (WG_PUB_A)
```

**Node B:**
```bash
docker exec peer_b bash -c "
    mkdir -p /peer_config/wg_keys
    wg genkey | tee /peer_config/wg_keys/wg_private.key | wg pubkey > /peer_config/wg_keys/wg_public.key
    echo 'Node B WG public key:'
    cat /peer_config/wg_keys/wg_public.key
"
# → copy Node B's WG public key (WG_PUB_B)
```

---

## Step 3 — Operator Runs ML-KEM Encapsulation Using Node B's Public Key

You do this locally — no container needed, just Python + liboqs installed.
OR run it inside one of the containers (doesn't matter — no secret key here).

```bash
MLKEM_PUB_B="<paste Node B's ML-KEM public key here>"

docker exec peer_a python3 /pq_handshake/pq_handshake.py encapsulate "$MLKEM_PUB_B"
# → prints two things — copy both:
#     CIPHERTEXT  (send to Node B)
#     PSK for Node A  (inject into Node A)
```

---

## Step 4 — Node B Decapsulates Using Its Secret Key

Node B's secret key never left Node B — we retrieve it from its keypair file.

```bash
SK_B=$(docker exec peer_b python3 /pq_handshake/pq_keygen.py show-secret)
CIPHERTEXT="<paste ciphertext from step 3>"

docker exec peer_b python3 /pq_handshake/pq_handshake.py decapsulate "$CIPHERTEXT"
# → prints PSK for Node B — must be IDENTICAL to PSK from step 3
```

---

## Step 5 — Configure Both WireGuard Interfaces with PSK

```bash
WG_PUB_A="<paste from step 2>"
WG_PUB_B="<paste from step 2>"
PSK_A="<paste from step 3>"    # same value as PSK_B
PSK_B="<paste from step 4>"    # verify it matches PSK_A!

docker exec peer_a bash /peer_config/configure.sh "$WG_PUB_B" "$PSK_A" "172.21.0.3:51820"
docker exec peer_b bash /peer_config/configure.sh "$WG_PUB_A" "$PSK_B" "172.21.0.2:51820"
```

---

## Step 6 — Test the Tunnel

```bash
docker exec peer_a ping -c 4 10.0.0.2
docker exec peer_b ping -c 4 10.0.0.1
```

---

## Step 7 — Verify PSK is Active on Both Sides

```bash
docker exec peer_a wg show
docker exec peer_b wg show
```

Both must show: `preshared key: (hidden)`
