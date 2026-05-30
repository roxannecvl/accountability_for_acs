# `prove_verify/`

Side-by-side prove/verify benchmarks of the credential proof used in the
thesis, in two backends:

- **`zk-friendly/`** — Circom + Groth16 (rapidsnark prover, snarkjs verifier).
  Poseidon / EdDSA-Poseidon / BabyJub primitives.
- **`standard/`** — C++ Longfellow (Google Benchmark). Flat SHA-256
  commitment, ECDSA / P-256 signatures.

Each backend exposes the same two variants of the proof:

| Variant | What changes |
|---|---|
| `prove_verify` | Full proof **with CFT** (ID binding + ElGamal-style outputs `c1..c4`). |
| `prove_verify_no_cft` | Same proof **without CFT** (no ID binding, no ElGamal, fewer disclosed slots). |

The zk-friendly side also keeps a separate **`merkle_vs_flat_bench/`** sweep
that compares Poseidon-Merkle inclusion against a flat Poseidon fold over
varying `total_attrs` / `used_attrs`.

## Reading results

Pre-recorded summaries from the two reference machines live under
`results/`:

```
results/
├── mobile-machine/     # docker run --cpus=2 --memory=4g
│   ├── standard_prove_verify.json
│   ├── standard_prove_verify_no_cft.json
│   ├── zk_friendly_merkle_vs_flat.json
│   ├── zk_friendly_prove_verify.json
│   └── zk_friendly_prove_verify_no_cft.json
└── server-machine/     # docker run --cpus=8 --memory=16g
    └── (same set of files)
```

## Reproducing

See the per-backend READMEs for full instructions, including local builds and
Docker:

- `standard/README.md`
- `zk-friendly/README.md`

Quick recap for Docker: build each image once, then run the benchmarks with
the resource profile that matches the target machine. You **must** pass both
`--cpus` and `--memory`.

| Profile | Flags |
|---|---|
| Mobile-like | `--cpus=2 --memory=4g` |
| Server-like | `--cpus=8 --memory=16g` |
