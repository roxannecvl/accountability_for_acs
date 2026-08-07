#!/usr/bin/env node
"use strict";

/**
 * Communication-cost report for zk-friendly Groth16 (same schema as standard):
 *   - CFT-only prove_verify
 *   - prove_verify + packed revocation at 2^12, 2^16, 2^20, 2^24
 *
 * Groth16 |π| is circuit-independent (128 B compressed); public IO is fixed
 * across revocation scales (Merkle path / leaf witnesses are private).
 *
 * Usage (from prove-verify/zk-friendly/):
 *   npm run bench:communication-size
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ZK_ROOT = path.join(__dirname, "..");
const OUT_DIR = process.env.ARTIFACTS_DIR
  ? path.isAbsolute(process.env.ARTIFACTS_DIR)
    ? process.env.ARTIFACTS_DIR
    : path.join(ZK_ROOT, process.env.ARTIFACTS_DIR)
  : path.join(__dirname, "artifacts_measure_communication_size");
const CFT_JSON = path.join(OUT_DIR, "cft_only.json");
const REVOC_JSON = path.join(OUT_DIR, "revocation.json");
const SUMMARY_JSON = path.join(OUT_DIR, "summary_latest.json");

const CFT_DEMO_DIR = path.join(ZK_ROOT, "prove-verify");
const CFT_ARTIFACTS = path.join(CFT_DEMO_DIR, "artifacts_bench_prove_verify");
const REVOC_DIR = path.join(ZK_ROOT, "prove-verify-revocation");
const REVOC_ARTIFACTS = path.join(REVOC_DIR, "artifacts_bench_prove_verify_revocation");

const DEFAULT_SCALES = [12, 16, 20, 24];
const GROTH16_COMPRESSED = 32 + 64 + 32; // G1 || G2 || G1
const CFT_FIELD_ELEMENTS = 9;
const CFT_BYTES = CFT_FIELD_ELEMENTS * 32;

function parseScales() {
  const raw = process.env.REVOC_LOG2_LIST ?? process.env.REVOC_LOG2;
  if (!raw) return DEFAULT_SCALES;
  return String(raw)
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n));
}

function packedDepth(revocLog2, bitsPerLeaf = 253) {
  const population = 1 << revocLog2;
  const numLeaves = Math.ceil(population / bitsPerLeaf);
  let padded = 1;
  while (padded < numLeaves) padded <<= 1;
  return Math.log2(padded);
}

function run(cmd, args, opts) {
  console.log(`\n$ ${cmd} ${args.join(" ")}`);
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...opts,
  });
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (exit ${r.status})`);
  }
}

/** Linear fit |π| ≈ a*d + b over packed Merkle depth d (same as standard). */
function fitVsDepth(byScale) {
  const n = byScale.length;
  if (n < 2) return null;
  let sumX = 0;
  let sumY = 0;
  let sumXX = 0;
  let sumXY = 0;
  for (const row of byScale) {
    const x = row.merkleDepth;
    const y = row.serializedProofBytes;
    sumX += x;
    sumY += y;
    sumXX += x * x;
    sumXY += x * y;
  }
  const denom = n * sumXX - sumX * sumX;
  if (denom === 0) return null;
  const a = (n * sumXY - sumX * sumY) / denom;
  const b = (sumY - a * sumX) / n;

  let ssTot = 0;
  let ssRes = 0;
  const meanY = sumY / n;
  let maxAbsRel = 0;
  for (const row of byScale) {
    const pred = a * row.merkleDepth + b;
    const err = row.serializedProofBytes - pred;
    ssRes += err * err;
    ssTot += (row.serializedProofBytes - meanY) ** 2;
    const rel = Math.abs(err) / row.serializedProofBytes;
    if (rel > maxAbsRel) maxAbsRel = rel;
  }
  const r2 = ssTot === 0 ? 1 : 1 - ssRes / ssTot;
  const d29 = 22; // packed depth for N=2^29 with B=253
  return {
    formula: `|pi| ≈ ${Math.round(a)}*d + ${Math.round(b)} bytes  (~${(a / 1024).toFixed(1)} KB*d + ${(b / 1024).toFixed(0)} KB)`,
    r2: Math.round(r2 * 1e4) / 1e4,
    maxAbsRelErrorPct: Math.round(maxAbsRel * 10000) / 100,
    extrapolated_2_29_d22_bytes: Math.round(a * d29 + b),
  };
}

function measureCftOnly() {
  console.log("=== CFT-only prove_verify ===");
  run("node", ["bench_prove_verify.js"], {
    cwd: CFT_DEMO_DIR,
    env: {
      ...process.env,
      BENCH_N: "1",
      BENCH_WARMUP: "0",
      KEEP_ARTIFACTS: "1",
    },
  });

  const iterDir = path.join(CFT_ARTIFACTS, "iter_0000");
  const publicJson = path.join(iterDir, "public.json");
  if (!fs.existsSync(publicJson)) {
    throw new Error(`Missing ${publicJson}`);
  }

  const publicArr = JSON.parse(fs.readFileSync(publicJson, "utf8"));
  const publicBinaryBytes = publicArr.length * 32;

  return {
    circuit: "prove_verify (age-check + CFT)",
    proof: {
      serializedProofBytes: GROTH16_COMPRESSED,
      note: "canonical BN254 Groth16 compressed (32+64+32)",
    },
    publicInputs: {
      count: publicArr.length,
      binaryBytes: publicBinaryBytes,
      cftBytes: CFT_BYTES,
    },
    showMessageIfProofPlusAllPublic: GROTH16_COMPRESSED + publicBinaryBytes,
    showMessageIfProofPlusCftOnlyCachedKeys: GROTH16_COMPRESSED + CFT_BYTES,
  };
}

function findRevocationIterDir(revocLog2) {
  const needle = `_l${revocLog2}_iter_0000`;
  if (!fs.existsSync(REVOC_ARTIFACTS)) return null;
  const matches = fs
    .readdirSync(REVOC_ARTIFACTS)
    .filter((name) => name.endsWith(needle))
    .map((name) => path.join(REVOC_ARTIFACTS, name));
  if (!matches.length) return null;
  matches.sort();
  return matches[0];
}

function measureRevocation(scales) {
  console.log("=== prove_verify + packed revocation ===");
  run("node", ["bench_prove_verify_revocation.js"], {
    cwd: REVOC_DIR,
    env: {
      ...process.env,
      BENCH_N: "1",
      BENCH_WARMUP: "0",
      REVOC_LOG2_LIST: scales.join(","),
      NODE_OPTIONS:
        process.env.NODE_OPTIONS || "--max-old-space-size=8192",
    },
  });

  const byScale = [];
  let publicInputsBytes = null;
  for (const revocLog2 of scales) {
    const iterDir = findRevocationIterDir(revocLog2);
    if (!iterDir) {
      throw new Error(`No revocation artifacts for 2^${revocLog2} under ${REVOC_ARTIFACTS}`);
    }
    const publicJson = path.join(iterDir, "public.json");
    const publicArr = JSON.parse(fs.readFileSync(publicJson, "utf8"));
    const pubBytes = publicArr.length * 32;
    if (publicInputsBytes == null) publicInputsBytes = pubBytes;
    byScale.push({
      revocLog2,
      merkleDepth: packedDepth(revocLog2),
      serializedProofBytes: GROTH16_COMPRESSED,
    });
  }

  return {
    circuit: "prove_verify + CFT + packed status-list",
    cftBytes: CFT_BYTES,
    publicInputsBytes,
    byScale,
  };
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const scales = parseScales();

  const cftOnly = measureCftOnly();
  const revocation = measureRevocation(scales);

  const withRevocation = {
    ...revocation,
    fitVsDepth: fitVsDepth(revocation.byScale),
  };

  const report = {
    meta: { type: "zk-friendly" },
    cftOnly,
    withRevocation,
  };

  const ts = new Date().toISOString().replaceAll(":", "-");
  fs.writeFileSync(CFT_JSON, JSON.stringify(cftOnly, null, 2) + "\n");
  fs.writeFileSync(REVOC_JSON, JSON.stringify(revocation, null, 2) + "\n");
  fs.writeFileSync(path.join(OUT_DIR, `summary_${ts}.json`), JSON.stringify(report, null, 2) + "\n");
  fs.writeFileSync(SUMMARY_JSON, JSON.stringify(report, null, 2) + "\n");

  console.log("\n=== communication-size summary ===");
  console.log(JSON.stringify(report, null, 2));
  console.log(`\nWrote ${SUMMARY_JSON}`);
}

main();
