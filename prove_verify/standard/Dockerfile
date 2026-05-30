# Build context: prove_verify/standard/
#
# `node:20-bookworm` ships multi-arch manifests, so this image builds natively
# on whatever host architecture you run on:
#   docker build -t standard-prove-verify .
#
# Debian bookworm is used (not bullseye) because the upstream Longfellow tree
# needs a recent clang.
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
