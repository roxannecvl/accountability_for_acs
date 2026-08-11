# Frontdoors, Not Backdoors: Accountable Anonymity for National Digital Identity

Companion code for the paper **"Frontdoors, Not Backdoors: Accountable Anonymity
for National Digital Identity"**. This repository contains the benchmarks
reported in the paper.

## Layout

- [`prove-verify/`](prove-verify/) — proof **generation** and **verification**
  benchmarks (zk-friendly Circom/Groth16 backend and Longfellow C++ backend,
  both with a CFT, a no-CFT, and a CFT + non-revocation proof variant).
- [`revocation/`](revocation/) — **anonymity revocation** benchmarks
  (direct decrypt, link decrypt, and MP-SPDZ-based MPC decrypt).

See the README inside each folder for build, run, and Docker instructions.
