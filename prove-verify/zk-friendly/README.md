# zk-friendly (Circom / Groth16)

Age-check presentation benchmarks: witness + rapidsnark prove + snarkjs verify.

## Setup

Needs Node 20+, `circom`, rapidsnark `prover` on `PATH`, and
`powersOfTau/powersOfTau28_hez_final_19.ptau` (`bash scripts/fetch_ptau.sh`).

```bash
cd prove-verify/zk-friendly
npm install
```

## Benchmarks

```bash
npm run bench:prove-verify
npm run bench:prove-verify-no-cft
npm run bench:prove-verify-revocation
npm run bench:merkle-vs-flat
npm run bench:communication-size
```

| Env | Default | Meaning |
|-----|---------|---------|
| `BENCH_N` | `10` | Measured iterations (+1 warmup) |
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
| `scripts/` | `clean.sh`, `fetch_ptau.sh`, … |

## Docker

```bash
cd prove-verify/zk-friendly
bash scripts/fetch_ptau.sh   # once, if powersOfTau/ is empty
docker build -t zk-friendly-bench -f Dockerfile .
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
docker run --rm --cpus=2 --memory=4g --memory-swap=4g zk-friendly-bench \
  bash -lc 'cd /bench && npm run bench:prove-verify >/tmp/log 2>&1 \
    && cat prove-verify/artifacts_bench_prove_verify/summary_latest.json' \
  > zkfriendly_mobile_prove_verify_summary.json
```

```bash
# server-like
docker run --rm --cpus=8 --memory=16g --memory-swap=16g zk-friendly-bench \
  bash -lc 'cd /bench && npm run bench:prove-verify >/tmp/log 2>&1 \
    && cat prove-verify/artifacts_bench_prove_verify/summary_latest.json' \
  > zkfriendly_server_prove_verify_summary.json
```


## Clean

```bash
npm run clean          # drop proofs/witnesses + generated/ (keep summary_*.json)
npm run clean:results  # delete artifact folders (summaries too)
npm run clean:all      # proofs/witnesses + generated/ + summaries + node_modules
```

## License

Code in this folder is under the workspace **MIT** license (`../../LICENSE`).
