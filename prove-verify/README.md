# `prove-verify/`

Side-by-side prove/verify benchmarks for the credential presentation proof:

| Dir | Stack |
|-----|--------|
| `zk-friendly/` | Circom + Groth16 (rapidsnark / snarkjs) |
| `standard/` | Longfellow C++ (Google Benchmark) |

Both expose the same five commands (run from the stack dir after setup):

```bash
npm run bench:prove-verify            # age-check + CFT
npm run bench:prove-verify-no-cft     # same, no CFT
npm run bench:prove-verify-revocation # age-check + CFT + non revocation claim (2^12…2^24)
npm run bench:merkle-vs-flat          # attribute-commitment sweep
npm run bench:communication-size      # wire size (CFT + non revoc claim 2^12…2^24)
```

Pre-recorded summaries: `results/{mobile,server}-env/`, `results/proof-sizes/`.

See each stack README for Docker and local setup.
