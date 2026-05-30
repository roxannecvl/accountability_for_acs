# Build context: prove_verify/zk-friendly/
#
# `node:20-bullseye` ships multi-arch manifests, so this image builds natively
# on whatever host architecture you run on:
#   docker build -t zk-friendly-prove-verify .
#
# rapidsnark is built with `-DUSE_ASM=OFF` so the same source path is used on
# every arch (no separate amd64/arm64 image needed).
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

# Build rapidsnark (provides `prover`). USE_ASM=OFF so the same source path
# is used on every arch.
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
COPY powersOfTau/powersOfTau28_hez_final_19.ptau ./powersOfTau/powersOfTau28_hez_final_19.ptau

CMD ["bash"]
