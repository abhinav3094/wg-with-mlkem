FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# --- System dependencies ---
# cmake + ninja-build + gcc: needed to compile liboqs from C source
# python3-dev: needed so the Python wrapper can link against Python headers
# libssl-dev: liboqs uses OpenSSL's RNG internally
# git: to clone liboqs source
RUN apt-get update --fix-missing && apt-get install -y \
    wireguard-tools \
    python3 \
    python3-pip \
    python3-dev \
    tcpdump \
    iproute2 \
    net-tools \
    procps \
    iputils-ping \
    cmake \
    ninja-build \
    gcc \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Build liboqs C library from source ---
# We must build the shared library (.so) before the Python wrapper can use it.
# -DBUILD_SHARED_LIBS=ON: build liboqs.so (shared), not liboqs.a (static)
#   The Python ctypes wrapper requires a shared library — it cannot use a static .a
# -DOQS_DIST_BUILD=ON: disables CPU feature detection that can fail in containers
# -DCMAKE_BUILD_TYPE=Release: optimized build, not debug
# --parallel 4: use 4 CPU cores to speed up compilation
RUN git clone --depth=1 \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs \
          -B /tmp/liboqs/build \
          -DBUILD_SHARED_LIBS=ON \
          -DOQS_DIST_BUILD=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -GNinja && \
    cmake --build /tmp/liboqs/build --parallel 4 && \
    cmake --build /tmp/liboqs/build --target install && \
    ldconfig && \
    rm -rf /tmp/liboqs

# --- Install liboqs-python wrapper ---
# liboqs-python is NOT on PyPI as a simple package.
# We clone it and install it directly.
# It wraps the C library we just installed using Python's ctypes.
RUN git clone --depth=1 \
    https://github.com/open-quantum-safe/liboqs-python.git /tmp/liboqs-python && \
    pip3 install /tmp/liboqs-python && \
    rm -rf /tmp/liboqs-python

# --- Install remaining Python dependencies ---
# cryptography: for HMAC-BLAKE2b key derivation (unchanged from before)
RUN pip3 install cryptography

# Verify the full round-trip works at build time.
# If this fails, the Docker build fails — no silent breakage.
RUN printf '%s\n' \
 'import oqs' \
    'kem = oqs.KeyEncapsulation("ML-KEM-768")' \
    'pk = kem.generate_keypair()' \
    'sk = kem.export_secret_key()' \
    'ct, ss_enc = kem.encap_secret(pk)' \
    'ss_dec = kem.decap_secret(ct)' \
    'assert ss_enc == ss_dec, "KEM round-trip FAILED"' \
    'assert len(pk) == 1184, f"Wrong pk size: {len(pk)}"' \
    'assert len(ct) == 1088, f"Wrong ct size: {len(ct)}"' \
    'assert len(ss_enc) == 32, f"Wrong ss size: {len(ss_enc)}"' \
    'print("liboqs ML-KEM-768 round-trip OK")' \
    'print(f"  pk={len(pk)}B  sk={len(sk)}B  ct={len(ct)}B  ss={len(ss_enc)}B")' \
    > /tmp/test_oqs.py && python3 /tmp/test_oqs.py

WORKDIR /app
CMD ["sleep", "infinity"]
