# Build context: prove_verify/standard/
#
# Target: linux/arm64 (Apple Silicon, aarch64 VMs).
#   docker build --platform linux/arm64 -t standard-prove-verify .
#
# On amd64 hosts the same command emulates via QEMU. Debian bookworm is
# required because Bullseye's default clang is too old for this tree's
# AArch64 NEON intrinsics (e.g. gf2k/sysdep.h).
FROM node:20-bookworm

WORKDIR /bench

ENV DEBIAN_FRONTEND=noninteractive
ENV CXX=clang++

# C++ toolchain + Google Test / Benchmark (same stack as Longfellow lib README).
RUN exec 3>&- ; apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates \
    clang cmake git make \
    libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Only what CMake + the benchmarks need.
COPY longfellow-zk/lib/ /bench/lib/
COPY scripts/ /bench/scripts/

RUN cmake -S /bench/lib -B /bench/clang-build-release \
      -DCMAKE_BUILD_TYPE=Release \
  && cmake --build /bench/clang-build-release -j"$(nproc)"

CMD ["bash"]
