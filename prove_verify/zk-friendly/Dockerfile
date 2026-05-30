# Build context: prove_verify/zk-friendly/
#
# Target: linux/arm64 (Apple Silicon, aarch64 VMs).
#   docker build --platform linux/arm64 -t zk-friendly-prove-verify .
#
# On amd64 hosts the same command emulates via QEMU. A separate amd64 image
# would be needed for native x86; rapidsnark's NASM (x86_64) path is disabled
# here (`-DUSE_ASM=OFF`) because it does not apply on aarch64.
FROM node:20-bullseye

WORKDIR /bench

# System deps for circom + rapidsnark build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl git \
    build-essential cmake pkg-config \
    libgmp-dev nlohmann-json3-dev \
    python3 \
 && rm -rf /var/lib/apt/lists/*

# Rust toolchain for circom.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install circom from source.
RUN git clone --depth 1 https://github.com/iden3/circom.git /tmp/circom \
 && cd /tmp/circom \
 && cargo build --release \
 && install -m 0755 target/release/circom /usr/local/bin/circom \
 && rm -rf /tmp/circom

# Build rapidsnark (provides `prover`). USE_ASM=OFF because the upstream
# x86_64 NASM path is not usable on aarch64.
RUN git clone --depth 1 https://github.com/iden3/rapidsnark.git /tmp/rapidsnark \
 && cd /tmp/rapidsnark \
 && git submodule update --init --recursive \
 && mkdir -p build && cd build \
 && cmake .. -DCMAKE_BUILD_TYPE=Release -DUSE_ASM=OFF \
 && make -j2 \
 && install -m 0755 src/prover /usr/local/bin/prover \
 && rm -rf /tmp/rapidsnark

# Install JS deps first so the layer is cached across source edits.
COPY package.json package-lock.json* ./
RUN npm install

# Copy the rest of the benchmark suite (lib, scripts, circuits, etc.).
COPY lib/ ./lib/
COPY scripts/ ./scripts/
COPY merkle_vs_flat_bench/ ./merkle_vs_flat_bench/
COPY prove_verify/ ./prove_verify/
COPY prove_verify_no_cft/ ./prove_verify_no_cft/

# Powers-of-tau file used by all three benchmarks. The host symlink/file at
# powersOfTau/powersOfTau28_hez_final_19.ptau must exist before the build
# (see README; `scripts/fetch_ptau.sh` downloads it if needed).
COPY powersOfTau/powersOfTau28_hez_final_19.ptau ./powersOfTau/powersOfTau28_hez_final_19.ptau

CMD ["bash"]
