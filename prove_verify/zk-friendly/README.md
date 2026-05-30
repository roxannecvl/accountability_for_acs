# ZK-friendly prove/verify benchmarks

Circom + Groth16 (rapidsnark prover, snarkjs verifier) drivers for the three
prove/verify experiments used in the thesis. Each benchmark measures, per
iteration (in ms):

- **witness** — C++ witness generation from Circom
- **prove** — rapidsnark `prover` (Groth16)
- **verify** — in-process `snarkjs.groth16.verify` (includes parsing
  `proof.json` + `public.json`; verification key cached in memory)

## Layout

```
zk-friendly/
├── lib/                      # shared JS helpers (Poseidon, BabyJub, Merkle, zk_common)
├── powersOfTau/              # powersOfTau28_hez_final_19.ptau (not in git)
├── scripts/                  # clean.sh, clean_results.sh, fetch_ptau.sh
├── merkle_vs_flat_bench/     # Merkle vs flat-Poseidon attribute commitment
├── prove_verify/             # full credential proof, CFT variant (32 attrs, 7 disclosed)
├── prove_verify_no_cft/      # same proof minus CFT (32 attrs, 5 disclosed)
├── Dockerfile                # reproducible image (native to your host arch)
└── package.json              # npm run scripts
```

Each benchmark folder ends up with an `artifacts_bench_<name>/` next to its
JS file; the script auto-cleans everything except `summary_*.json` and
`summary_latest.json` unless you pass `--keep-artifacts`.

## What each benchmark proves

| Folder | Circuit | What is proved |
|---|---|---|
| `merkle_vs_flat_bench/` | generated `merkle_t<N>_u<K>.circom` / `flat_t<N>_u<K>.circom` | Merkle inclusion vs Poseidon-fold over `(name, value)` pairs. Sweeps `total ∈ {8,16,32,64}`, `used ∈ {1,2,4,8,16}` (skips `used > total`). |
| `prove_verify/` | `prove_verify.circom` | Full credential proof, **with CFT**: Poseidon fold over 32 `(claimName, claimValue)` pairs; EdDSA-Poseidon issuer signature; age / validity-window checks; EdDSA-Poseidon hardware signature; BabyJub ElGamal outputs `c1..c4`. 7 disclosed slots (0,1,4,5,6,14,15). |
| `prove_verify_no_cft/` | `prove_verify_no_cft.circom` | Same proof **without CFT**: drops ID binding + ElGamal relations + `c1..c4`. 5 disclosed slots (4,5,6,14,15); 6 zero-padded public inputs to keep snarkjs' verifier MSM window comparable to the CFT variant. |

## CLI flags and environment variables

### Shared (all three benchmarks)

| Name | Kind | Default | Meaning |
|---|---|---|---|
| `BENCH_N` | env | merkle: `10`, prove-verify: `20`, prove-verify-no-cft: `20` | Measured iterations per circuit / point. Prove-verify benchmarks also run **1 warm-up** iteration that is discarded from stats. |
| `--verbose` | flag | off | Print Circom/Groth16 setup sections, per-circuit min/avg/median/p95/max stats, and extra banners. |
| `--quiet` | flag | — | No-op (kept for compatibility); quiet console is the default. |
| `--keep-artifacts` | flag | off | Keep all generated files under `artifacts_bench_*/` and `generated/`. By default everything except `summary_*.json` / `summary_latest.json` is removed at the end of the run. |
| `KEEP_ARTIFACTS=1` | env | off | Same as `--keep-artifacts`. |
| `RAPIDSNARK_BIN` | env | `prover` | Path/name of the rapidsnark Groth16 prover. |
| `CIRCOM_BIN` / `CIRCOM` | env | `circom` | Circom compiler to invoke. |
| `SNARKJS_BIN` | env | auto | Used by `lib/zk_common.js` for the snarkjs CLI (`groth16 setup`, `zkey export verificationkey`). Defaults to `node_modules/.bin/snarkjs` if present, otherwise `snarkjs` on `PATH`. |

### Merkle vs flat only

| Name | Kind | Default | Meaning |
|---|---|---|---|
| `TOTAL_ATTRS` | env | `8,16,32,64` | Comma list of total attribute counts (each must be a power of two). |
| `USED_ATTRS` | env | `1,2,4,8,16` | Comma list of disclosure counts; `used > total` pairs are skipped. |
| `--clean` / `CLEAN=1` | flag/env | off | Before the sweep, wipe `generated/`, `artifacts_bench_merkle_vs_flat/`, and the generated `merkle_t*_u*.circom` / `flat_t*_u*.circom` source files. |
| `--compact` | flag | off | Omit some sweep banners with `--verbose`. |

### Output

- Quiet (default): a small header, one progress line per point (Merkle/flat) or no per-iteration lines (prove-verify), and `Summary written: …/summary_latest.json` at the end.
- `--verbose`: setup sections, per-iteration timings, full per-circuit stats (same aggregates as in `summary_latest.json` → `statsMs`).

## Docker

The Dockerfile pulls multi-arch `node:20-bullseye`, so the build naturally
matches whichever architecture the host runs on. rapidsnark is compiled with
`-DUSE_ASM=OFF`, so the same source path is used on every arch (no separate
amd64/arm64 image needed).

Build once from `prove_verify/zk-friendly/`:

```bash
docker build -t zk-friendly-prove-verify .
```

Pick the resource profile that matches the experiment:

- **Mobile-like:** `--cpus=2 --memory=4g`
- **Server-like:** `--cpus=8 --memory=16g`

You **must** pass both `--cpus` and `--memory` (any combination is fine; the
two profiles above are the ones used in the thesis).

The `bash -lc '… >/tmp/bench.log 2>&1 && cat .../summary_latest.json'` form
keeps benchmark console output inside the container and prints only the JSON
to host stdout, so you can redirect host stdout straight to a `.json` file.
Swap `--cpus=2 --memory=4g` for `--cpus=8 --memory=16g` for the server
profile (same command otherwise).

### Merkle vs flat

```bash
docker run --rm --cpus=2 --memory=4g zk-friendly-prove-verify \
  bash -lc 'cd /bench/merkle_vs_flat_bench && node bench_merkle_vs_flat.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_merkle_vs_flat/summary_latest.json' \
  > zk_friendly_merkle_vs_flat.json
```

### Prove / verify — CFT variant

```bash
docker run --rm --cpus=2 --memory=4g zk-friendly-prove-verify \
  bash -lc 'cd /bench/prove_verify && node bench_prove_verify.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify/summary_latest.json' \
  > zk_friendly_prove_verify.json
```

### Prove / verify — no-CFT variant

```bash
docker run --rm --cpus=2 --memory=4g zk-friendly-prove-verify \
  bash -lc 'cd /bench/prove_verify_no_cft && node prove_verify_no_cft.js >/tmp/bench.log 2>&1 \
    && cat artifacts_bench_prove_verify_no_cft/summary_latest.json' \
  > zk_friendly_prove_verify_no_cft.json
```

Pass other env vars (`BENCH_N`, `TOTAL_ATTRS`, …) inside the `bash -lc '…'`
string, or with `-e VAR=value` before the image name.
