# Anonymity revocation benchmarks

Baby Jubjub CFT revocation throughput (Node 18+). C4 binding matches zk-friendly `prove_verify.circom`.

| Dir | Experiment |
|-----|------------|
| `direct-decrypt/` | Decrypt every CFT (police + judge + NGO) |
| `link-decrypt/` | Link to PIDs, keep ≥10% recurring, decrypt those |
| `mpc/` | PET + MP-SPDZ predicate matrix (needs `MP_SPDZ_PATH`) |
| `lib/` | Shared crypto / experiment harness |
| `results/` | CSVs; PDFs under `results/plots/` |

## Setup

```bash
cd revocation
npm ci
npm run verify          # optional: link-decrypt protocol sanity check
```

## Benchmarks

```bash
npm run bench:direct-decrypt
npm run bench:link-decrypt
npm run experiment      # both (direct then link)

# MPC (requires local MP-SPDZ)
MP_SPDZ_PATH=/path/to/mp-spdz npm run bench:mpc
npm run mpc:summarize -- mpc/sweep_*/results.csv

npm run plot            # PDFs → results/plots/
```

| Env | Default | Meaning |
|-----|---------|---------|
| `EXPERIMENT_SIZES` | `10,20,50,100,500,1000,2000,4000,8000` | CFT set sizes (direct/link) |
| `EXPERIMENT_RUNS` | `10` | Runs per (size × recurring%) cell |
| `NUMS` | `10 20 50 100 200 500 1000` | CFT sizes for MPC sweep |
| `ITERATIONS` | `10` | Runs per size (MPC) |
| `TAU` | `2` | MPC predicate threshold |
| `MP_SPDZ_PATH` | — | Path to MP-SPDZ install (MPC) |

Smoke test:

```bash
EXPERIMENT_SIZES=100,500 EXPERIMENT_RUNS=2 npm run bench:direct-decrypt
```

Outputs: `results/{direct,link,mpc}-decrypt_{runs,summary,fit}.csv` and `results/plots/*_total_time.pdf`.

## Docker

```bash
cd revocation
docker build -t revocation-bench -f Dockerfile .
```

```bash
# server-like; bind-mount results/
mkdir -p results
docker run --rm --cpus=8 --memory=16g --memory-swap=16g \
  -v "$(pwd)/results:/bench/results" \
  revocation-bench \
  bash -lc 'npm run experiment'
```

## License

Code in this folder is under the workspace **MIT** license (`../LICENSE`).
