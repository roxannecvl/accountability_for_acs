# Anonymity revocation experiments

Two revocation throughput experiments on Baby Jubjub:

- **direct-decrypt** — decrypt every CFT (police + judge + NGO each partially decrypt all CFTs, then combine).
- **link-decrypt** — first link every CFT to a PID, keep only PIDs appearing in ≥ 10% of the set, then decrypt only those.
- **mpc-decrypt** — PET + MP-SPDZ predicate matrix (requires a local MP-SPDZ install via `MP_SPDZ_PATH`).

## Run (in order)

Requires Node 18.x with the pinned `@noble/curves@1.9.7` (see `package.json`).

```bash

# 1. from current directory: one-off install + sanity checks
npm ci
npm run check-env     # checks Base8 matches circom
npm run verify        # checks the link-decrypt protocol is correct

# 2. the two experiments (each does 9 sizes × 3 recurring% × 10 runs = 270 runs)
npm run experiment:direct-decrypt  
npm run experiment:link-decrypt     

# 3. figures
python3 plot_experiment_figures.py
```

Outputs to `results/`:

| File | Produced by |
|---|---|
| `direct-decrypt_runs.csv` / `_summary.csv` / `_fit.csv` / `_total_time.pdf` | `experiment:direct-decrypt` + `plot_experiment_figures.py` |
| `link-decrypt_runs.csv` / `_summary.csv` / `_fit.csv` / `_total_time.pdf` | `experiment:link-decrypt` + `plot_experiment_figures.py` |
| `mpc-decrypt_runs.csv` / `_summary.csv` / `_fit.csv` | `mpc:sweep` + `mpc:summarize` (included in combined plot) |

For **mpc-decrypt** (requires MP-SPDZ), run `MP_SPDZ_PATH=/path/to/mp-spdz npm run mpc:sweep` then `npm run mpc:summarize -- mpc/sweep_*/results.csv` to write the plot-ready CSVs into `results/`.

Optional knobs for a quick smoke test:

```bash
EXPERIMENT_SIZES=100,500 EXPERIMENT_RUNS=2 npm run experiment:direct-decrypt
```
