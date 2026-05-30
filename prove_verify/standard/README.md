# Standard (Longfellow) prove/verify benchmarks

> The Longfellow C++ code under `longfellow-zk/` was copied (and modified)
> from <https://github.com/google/longfellow-zk/tree/main> (Apache-2.0).

Google Benchmark drivers for the C++ credential-commitment proofs in a
trimmed [Longfellow](https://github.com/google/longfellow-zk) `lib/` tree.
Counterpart to the Circom + Groth16 drivers under `../zk-friendly/`.

Two benchmark binaries are exposed here:

| Variant | Folder / binary | What is proved |
|---|---|---|
| **CFT** | `bench_prove_verify.js` → `prove_verify_test` | Flat SHA-256 over 32 attribute slots (7 disclosed: 0,1,4,5,6,14,15), issuer ECDSA/P-256 over the flat digest, age / validity-window checks, P-256 ElGamal relations on public `c1..c4`, hardware ECDSA/P-256 over public `m`. |
| **no-CFT** | `bench_prove_verify_no_cft.js` → `prove_verify_no_cft_test` | Same flat SHA-256 commitment and issuer/hardware ECDSA, but no ID binding and no ElGamal / `c1..c4` (5 disclosed slots: 4,5,6,14,15). |

Each script mirrors the corresponding zk-friendly benchmark
(`../zk-friendly/prove_verify/bench_prove_verify.js` and
`../zk-friendly/prove_verify_no_cft/prove_verify_no_cft.js`).

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
├── Dockerfile                # reproducible image (native to your host arch)
└── .gitignore                # clang-build-release/ + artifacts_bench_*
```

Each script writes its summary under `prove_verify/standard/`:

- `artifacts_bench_prove_verify/summary_latest.json`
- `artifacts_bench_prove_verify_no_cft/summary_latest.json`

Override the directory with `ARTIFACTS_DIR=...` or `--out-dir ...` (relative
paths resolve against `prove_verify/standard/`).

## Defaults

Both scripts share the same defaults:

- 20 outer repetitions (`BENCH_N` / `--n` / `--repetitions`)
- 1 inner iteration per repetition (`BENCH_ITERATIONS` / `--iterations`; use
  `0` or `auto` for adaptive)
- `min_time = 0.05s` (`BENCH_MIN_TIME` / `--min_time`)
- 1 extra Google Benchmark repetition is run before the measured pass and
  discarded; set `BENCH_WARMUP=0` to skip
- All passes use `--benchmark_format=console` plus `--benchmark_out` into a
  temp file: live GB table on stdout, measured JSON parsed afterwards into
  `summary_<timestamp>.json` + `summary_latest.json`
- Cleanup keeps only the summary JSONs; `--keep-artifacts` keeps everything
  under `artifacts_bench_*/`

## Environment variables

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

## Google Benchmark names

Each binary exposes three benchmarks:

| CFT name | no-CFT name | What is timed |
|---|---|---|
| `BM_ProveVerifyProver_P256` | `BM_ProveVerifyNoCftProver_P256` | One **prove** per iteration (witness generation inside). |
| `BM_ProveVerifyVerifier_P256` | `BM_ProveVerifyNoCftVerifier_P256` | One prove **outside** the loop, then **verify-only** per iteration. |
| `BM_ProveVerifyFullCycle_P256` | `BM_ProveVerifyNoCftFullCycle_P256` | **Prove + verify** each iteration. |

## Docker

The Dockerfile pulls multi-arch `node:20-bookworm`, so the build naturally
matches whichever architecture the host runs on. Build once from
`prove_verify/standard/`:

```bash
docker build -t standard-prove-verify .
```

Pick the resource profile that matches the experiment:

- **Mobile-like:** `--cpus=2 --memory=4g`
- **Server-like:** `--cpus=8 --memory=16g`

The `bash -lc '… >/tmp/bench.log 2>&1 && cat .../summary_latest.json'` form
keeps benchmark console output inside the container and prints only the JSON
to host stdout, so you can redirect host stdout straight to a `.json` file.

### CFT variant

```bash
docker run --rm --cpus=2 --memory=4g standard-prove-verify \
  bash -lc 'cd /bench && BENCH_N=10 BENCH_MIN_TIME=0.05s \
    node scripts/bench_prove_verify.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify/summary_latest.json' \
  > standard_prove_verify.json
```

Swap `--cpus=2 --memory=4g` for `--cpus=8 --memory=16g` for the server
profile (same command otherwise).

### no-CFT variant

```bash
docker run --rm --cpus=2 --memory=4g standard-prove-verify \
  bash -lc 'cd /bench && BENCH_N=10 BENCH_MIN_TIME=0.05s \
    node scripts/bench_prove_verify_no_cft.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify_no_cft/summary_latest.json' \
  > standard_prove_verify_no_cft.json
```

Pass other env vars (`BENCH_FILTER`, `ARTIFACTS_DIR`, …) inside the
`bash -lc '…'` string, or with `-e VAR=value` before the image name.
