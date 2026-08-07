# Build: cd prove-verify/standard && docker build -t standard-bench -f Dockerfile .
#
#   docker run --rm --cpus=2 --memory=4g --memory-swap=4g standard-bench \
#     bash -lc 'cd /bench && npm run bench:prove-verify >/tmp/log 2>&1 \
#       && cat prove-verify/artifacts_bench_prove_verify/summary_latest.json'
# Scripts: bench:prove-verify | bench:prove-verify-no-cft | bench:prove-verify-revocation | bench:merkle-vs-flat | bench:communication-size
#
FROM node:20-bookworm

WORKDIR /bench

ENV DEBIAN_FRONTEND=noninteractive

# C++ toolchain + Google Test / Benchmark (same stack as Longfellow lib README).
RUN exec 3>&- ; apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates \
    clang cmake git make \
    libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

ENV CXX=clang++

ENV LONGFELLOW_BUILD_DIR=/bench/clang-build-release
ENV LONGFELLOW_CRED_BENCH_BIN=${LONGFELLOW_BUILD_DIR}/circuits/tests/ec/prove_verify_test
ENV LONGFELLOW_NO_CFT_BENCH_BIN=${LONGFELLOW_BUILD_DIR}/circuits/tests/ec/prove_verify_no_cft_test
ENV LONGFELLOW_ATTR_BENCH_BIN=${LONGFELLOW_BUILD_DIR}/circuits/tests/ec/attr_commitment_experiment_test
ENV LONGFELLOW_REVOC_BENCH_BIN=${LONGFELLOW_BUILD_DIR}/circuits/tests/ec/prove_verify_revocation_test

# Build context: prove-verify/standard/
COPY longfellow-zk/lib/ /bench/lib/
COPY package.json /bench/
COPY scripts/ /bench/scripts/
COPY prove-verify/ /bench/prove-verify/
COPY prove-verify-no-cft/ /bench/prove-verify-no-cft/
COPY prove-verify-revocation/ /bench/prove-verify-revocation/
COPY merkle-vs-flat/ /bench/merkle-vs-flat/
COPY communication-costs/ /bench/communication-costs/

RUN cmake -S /bench/lib -B "${LONGFELLOW_BUILD_DIR}" \
      -DCMAKE_BUILD_TYPE=Release \
  && cmake --build "${LONGFELLOW_BUILD_DIR}" \
      --target prove_verify_test prove_verify_no_cft_test attr_commitment_experiment_test prove_verify_revocation_test -j"$(nproc)" \
  && test -x "${LONGFELLOW_CRED_BENCH_BIN}" \
  && test -x "${LONGFELLOW_NO_CFT_BENCH_BIN}" \
  && test -x "${LONGFELLOW_ATTR_BENCH_BIN}" \
  && test -x "${LONGFELLOW_REVOC_BENCH_BIN}"

CMD ["bash"]
