# Standard (Longfellow) prove/verify benchmarks

Google Benchmark drivers for the C++ credential-commitment proofs in a
trimmed [Longfellow](https://github.com/google/longfellow-zk) `lib/` tree.
Counterpart to the Circom + Groth16 drivers under
`../zk-friendly/`.

Two benchmark binaries are exposed here:

| Variant | Folder / binary | What is proved |
|---|---|---|
| **CFT** | `bench_prove_verify.js` → `prove_verify_test` | Flat SHA-256 over 32 attribute slots (7 disclosed: 0,1,4,5,6,14,15), issuer ECDSA/P-256 over the flat digest, age / validity-window checks, BabyJub-free P-256 ElGamal relations on public `c1..c4`, hardware ECDSA/P-256 over public `m`. |
| **no-CFT** | `bench_prove_verify_no_cft.js` → `prove_verify_no_cft_test` | Same flat SHA-256 commitment and issuer/hardware ECDSA, but no ID binding and no ElGamal / `c1..c4` (5 disclosed slots: 4,5,6,14,15). |

Each script timing-wise mirrors the corresponding zk-friendly benchmark:

- `prove_verify/standard/bench_prove_verify.js` ↔ `prove_verify/zk-friendly/prove_verify/bench_prove_verify.js`
- `prove_verify/standard/bench_prove_verify_no_cft.js` ↔ `prove_verify/zk-friendly/prove_verify_no_cft/prove_verify_no_cft.js`

## Layout

```
standard/
├── longfellow-zk/            # trimmed C++ source tree (cmake / clang build)
│   └── lib/circuits/tests/ec/
│       ├── prove_verify_{shared.cc,shared.h,test.cc}         # CFT
│       └── prove_verify_no_cft_{shared.cc,shared.h,test.cc}  # no-CFT
├── scripts/
│   ├── bench_prove_verify.js          # CFT variant driver
│   └── bench_prove_verify_no_cft.js   # no-CFT variant driver
├── Dockerfile                # linux/arm64 reproducible image
└── .gitignore                # clang-build-release/ + artifacts_bench_*
```

Each script writes its summary under `prove_verify/standard/`:

- `artifacts_bench_prove_verify/summary_latest.json`
- `artifacts_bench_prove_verify_no_cft/summary_latest.json`

Override the directory with `ARTIFACTS_DIR=...` or `--out-dir ...` (relative
paths resolve against `prove_verify/standard/`).

## Local build

Skip this section if you're running through Docker.

System deps (Debian/Ubuntu):

```bash
sudo apt install -y clang cmake libssl-dev libzstd-dev \
                    libgtest-dev libbenchmark-dev zlib1g-dev
```

macOS:

```bash
brew install googletest google-benchmark zstd
```

Build the C++ tree (from `prove_verify/standard/longfellow-zk/`):

```bash
cmake -S lib -B clang-build-release -DCMAKE_BUILD_TYPE=Release
cmake --build clang-build-release -j 8
```

This produces the benchmark binaries under
`longfellow-zk/clang-build-release/circuits/tests/ec/`:

- `prove_verify_test`
- `prove_verify_no_cft_test`

If the binaries are missing the Node scripts exit with the expected path
printed; override with `--bin PATH` or `LONGFELLOW_CRED_BENCH_BIN`.

## Running the benchmarks

From `prove_verify/standard/`:

```bash
node scripts/bench_prove_verify.js --help
node scripts/bench_prove_verify_no_cft.js --help
```

Default behaviour for both scripts:

- 20 outer repetitions (`BENCH_N` / `--n` / `--repetitions`)
- 1 inner iteration per repetition (`BENCH_ITERATIONS` / `--iterations`; use
  `0` or `auto` for adaptive)
- `min_time = 0.05s` (`BENCH_MIN_TIME` / `--min_time`)
- 1 extra Google Benchmark repetition is run before the measured pass and
  discarded; set `BENCH_WARMUP=0` to skip
- All passes use `--benchmark_format=console` plus `--benchmark_out` into a
  temp file: you get the **live** GB table on stdout while the measured JSON
  is parsed afterwards into `summary_<timestamp>.json` + `summary_latest.json`
- Cleanup keeps only the summary JSONs; pass `--keep-artifacts` to keep
  everything in `artifacts_bench_*/`

Common environment variables (both scripts):

| Variable | Meaning |
|---|---|
| `BENCH_N` | Outer GB repetitions → `--benchmark_repetitions` (default 20). Alias: `BENCH_REPETITIONS`. |
| `BENCH_ITERATIONS` | Inner iterations → `--benchmark_iterations` (default 1; `0` / `auto` = adaptive). |
| `BENCH_MIN_TIME` | e.g. `0.05s`, `0.2s`. |
| `BENCH_FILTER` | Regex. Defaults: `BM_ProveVerify(Prover\|Verifier\|FullCycle)_P256.*` (CFT; the suffix anchor avoids matching the no-CFT names) or `BM_ProveVerifyNoCft.*` (no-CFT). |
| `BENCH_METRIC` | `real_time` / `cpu_time` / `both` — affects `--verbose printStats` only. |
| `ARTIFACTS_DIR` | Subdir under `prove_verify/standard/` or absolute path. |
| `LONGFELLOW_CRED_BENCH_BIN` | Path to the benchmark binary. |
| `KEEP_ARTIFACTS` | With `--keep-artifacts`. |
| `CLEAN` | With `--clean`: wipe the artifact dir before the run. |
| `BENCH_WARMUP` | `0`/`false`/`no` to skip the warm-up repetition. |

Useful CLI flags: `--verbose`, `--quiet` (no-op), `--compact`,
`--keep-artifacts`, `--clean`, `--bin`, `--filter`, `--repetitions` / `--n`,
`--iterations` (or `auto`), `--min_time`, `--metric`, `--out-dir`.

### Google Benchmark names

Each binary exposes three benchmarks (CFT shown; no-CFT has `NoCft` inserted
before each kind):

| CFT name | no-CFT name | What is timed |
|---|---|---|
| `BM_ProveVerifyProver_P256` | `BM_ProveVerifyNoCftProver_P256` | One **prove** per iteration (witness generation inside). |
| `BM_ProveVerifyVerifier_P256` | `BM_ProveVerifyNoCftVerifier_P256` | One prove **outside** the loop, then **verify-only** per iteration. |
| `BM_ProveVerifyFullCycle_P256` | `BM_ProveVerifyNoCftFullCycle_P256` | **Prove + verify** each iteration. |

### Local examples

CFT only, custom repetitions:

```bash
BENCH_N=30 BENCH_MIN_TIME=0.2s \
  node scripts/bench_prove_verify.js \
  --filter 'BM_ProveVerifyFullCycle_P256.*'
```

no-CFT, override binary path:

```bash
node scripts/bench_prove_verify_no_cft.js \
  --bin longfellow-zk/clang-build-release/circuits/tests/ec/prove_verify_no_cft_test \
  --repetitions 20 --min_time 0.2s
```

Raw smoke test directly against the binary:

```bash
cd longfellow-zk
./clang-build-release/circuits/tests/ec/prove_verify_test \
  --benchmark_filter='BM_ProveVerifyFullCycle_P256' \
  --benchmark_min_time=0.001s --benchmark_iterations=1
```

## Docker

Reproducible **`linux/arm64`** image. Debian **bookworm** is required because
Bullseye's default clang is too old for this tree's AArch64 NEON intrinsics.
On amd64 hosts the same command runs under QEMU.

### Build the image

Run from `prove_verify/standard/`:

```bash
docker build --platform linux/arm64 -t standard-prove-verify .
```

Inside the container:

- `WORKDIR /bench`
- `lib/` and `scripts/` copied from the build context
- Binaries at `/bench/clang-build-release/circuits/tests/ec/...`
- Summaries default to `/bench/artifacts_bench_prove_verify/` and
  `/bench/artifacts_bench_prove_verify_no_cft/`

### Run a benchmark

Pick the resource profile that matches the experiment you want.

- **Mobile-like:** `--cpus=2 --memory=4g`
- **Server-like:** `--cpus=8 --memory=16g`

You **must** pass both `--cpus` and `--memory` (any combination is fine; the
two profiles above are the ones used in the thesis).

The `bash -lc '… >/tmp/bench.log 2>&1 && cat .../summary_latest.json'` form
sends benchmark console output inside the container and prints only the JSON
to host stdout, so you can redirect host stdout straight to a `.json` file.

#### Prove / verify — CFT variant

Mobile:

```bash
docker run --rm --platform linux/arm64 --cpus=2 --memory=4g standard-prove-verify \
  bash -lc 'cd /bench && BENCH_N=10 BENCH_MIN_TIME=0.05s \
    node scripts/bench_prove_verify.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify/summary_latest.json' \
  > standard_prove_verify.json
```

Server:

```bash
docker run --rm --platform linux/arm64 --cpus=8 --memory=16g standard-prove-verify \
  bash -lc 'cd /bench && BENCH_N=10 BENCH_MIN_TIME=0.05s \
    node scripts/bench_prove_verify.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify/summary_latest.json' \
  > standard_prove_verify.json
```

#### Prove / verify — no-CFT variant

Mobile:

```bash
docker run --rm --platform linux/arm64 --cpus=2 --memory=4g standard-prove-verify \
  bash -lc 'cd /bench && BENCH_N=10 BENCH_MIN_TIME=0.05s \
    node scripts/bench_prove_verify_no_cft.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify_no_cft/summary_latest.json' \
  > standard_prove_verify_no_cft.json
```

Server:

```bash
docker run --rm --platform linux/arm64 --cpus=8 --memory=16g standard-prove-verify \
  bash -lc 'cd /bench && BENCH_N=10 BENCH_MIN_TIME=0.05s \
    node scripts/bench_prove_verify_no_cft.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify_no_cft/summary_latest.json' \
  > standard_prove_verify_no_cft.json
```

### Watch progress, then `docker cp` the summary

Use a named container and **don't** pass `--rm`; `docker cp` works on a
stopped container until you `docker rm` it. The example below uses the
mobile profile; swap `--cpus`/`--memory` for the server profile.

```bash
docker run --name std-prove-verify -it --platform linux/arm64 \
  --cpus=2 --memory=4g standard-prove-verify \
  bash -lc 'cd /bench && node scripts/bench_prove_verify.js \
    --filter "BM_ProveVerifyFullCycle_P256.*" \
    --repetitions 5 --min_time 0.05s'

docker cp std-prove-verify:/bench/artifacts_bench_prove_verify/summary_latest.json \
  ./standard_prove_verify.json

docker rm std-prove-verify
```

If a run fails, `docker rm -f <name>` before reusing the same name. Pass
`BENCH_N`, `ARTIFACTS_DIR`, etc. with `-e VAR=value` before the image name if
you prefer env over `bash -lc '…'`.

### Cleaning

Inside or outside the container, delete `artifacts_bench_prove_verify*/`, or
pass `--clean` / `CLEAN=1` to wipe the relevant artifact dir before the run.
