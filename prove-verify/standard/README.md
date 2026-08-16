# standard (Longfellow)

Google Benchmark timings for the age-check presentation (P-256 + SHA-256).

## Setup

```bash
cd prove-verify/standard/longfellow-zk
cmake -S lib -B clang-build-release -DCMAKE_BUILD_TYPE=Release
cmake --build clang-build-release --target \
  prove_verify_test prove_verify_no_cft_test \
  attr_commitment_experiment_test prove_verify_revocation_test -j 8
```

## Benchmarks

From `prove-verify/standard/`:

```bash
npm run bench:prove-verify
npm run bench:prove-verify-no-cft
npm run bench:prove-verify-revocation
npm run bench:merkle-vs-flat
npm run bench:communication-size
```

| Env | Default | Meaning |
|-----|---------|---------|
| `BENCH_N` | `10` | Outer samples |
| `REVOC_LOG2_LIST` | `12,16,20,24` | Revocation population scales |
| `TOTAL_ATTRS` | `8,16,32,64` | merkle-vs-flat: credential sizes \(n\) |
| `USED_ATTRS` | `1,2,4,8,16` | merkle-vs-flat: disclosed counts \(k\) (skipped when \(k>n\)) |

| Folder | Role |
|--------|------|
| `prove-verify/` | age-check + CFT |
| `prove-verify-no-cft/` | no-CFT baseline |
| `prove-verify-revocation/` | + packed status-list |
| `merkle-vs-flat/` | attribute-commitment sweep |
| `communication-costs/` | wire-size measurement |
| `scripts/` | shared helpers + clean scripts |

## Docker

```bash
cd prove-verify/standard
docker build -t standard-bench -f Dockerfile .
```

| `npm run …` | `cat` path inside container |
|-------------|-----------------------------|
| `bench:prove-verify` | `prove-verify/artifacts_bench_prove_verify/summary_latest.json` |
| `bench:prove-verify-no-cft` | `prove-verify-no-cft/artifacts_bench_prove_verify_no_cft/summary_latest.json` |
| `bench:prove-verify-revocation` | `prove-verify-revocation/artifacts_bench_prove_verify_revocation/summary_latest.json` |
| `bench:merkle-vs-flat` | `merkle-vs-flat/artifacts_bench_merkle_vs_flat/summary_latest.json` |
| `bench:communication-size` | `communication-costs/artifacts_measure_communication_size/summary_latest.json` |

### Example with prove-verify

```bash
# mobile-like
docker run --rm --cpus=2 --memory=4g --memory-swap=4g standard-bench \
  bash -lc 'cd /bench && npm run bench:prove-verify >/tmp/log 2>&1 \
    && cat prove-verify/artifacts_bench_prove_verify/summary_latest.json' \
  > standard_mobile_prove_verify_summary.json
```

```bash
# server-like
docker run --rm --cpus=8 --memory=16g --memory-swap=16g standard-bench \
  bash -lc 'cd /bench && npm run bench:prove-verify >/tmp/log 2>&1 \
    && cat prove-verify/artifacts_bench_prove_verify/summary_latest.json' \
  > standard_server_prove_verify_summary.json
```

## Clean

```bash
npm run clean:results  # delete local artifact/summary folders (asks for confirmation)
npm run clean:all      # same + remove longfellow-zk/clang-build-release
```

## License

Benchmark harness and circuit wrappers here are under the workspace **MIT**
license (`../../LICENSE`). Vendored `longfellow-zk/` remains **Apache 2.0**
(Google LLC).
