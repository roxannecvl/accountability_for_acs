#!/usr/bin/env node
"use strict";

/**
 * Communication-cost report for Longfellow:
 *   - CFT-only prove_verify proof size
 *   - prove_verify + packed revocation at 2^12, 2^16, 2^20, 2^24
 *
 * Usage (from prove-verify/standard/):
 *   npm run bench:communication-size
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const STANDARD_ROOT = path.join(__dirname, "..");
const OUT_DIR = process.env.ARTIFACTS_DIR
  ? path.isAbsolute(process.env.ARTIFACTS_DIR)
    ? process.env.ARTIFACTS_DIR
    : path.join(STANDARD_ROOT, process.env.ARTIFACTS_DIR)
  : path.join(__dirname, "artifacts_measure_communication_size");
const CFT_JSON = path.join(OUT_DIR, "cft_only.json");
const REVOC_JSON = path.join(OUT_DIR, "revocation.json");
const SUMMARY_JSON = path.join(OUT_DIR, "summary_latest.json");

function runMeasure(scriptName, jsonOut) {
  const script = path.join(__dirname, scriptName);
  console.log(`\n=== ${scriptName} ===`);
  const r = spawnSync("bash", [script], {
    cwd: STANDARD_ROOT,
    env: {
      ...process.env,
      MEASURE_JSON_OUT: jsonOut,
      REVOC_LOG2_LIST: process.env.REVOC_LOG2_LIST || "12,16,20,24",
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.status !== 0) {
    throw new Error(`${scriptName} failed (exit ${r.status})`);
  }
  if (!fs.existsSync(jsonOut)) {
    throw new Error(`missing ${jsonOut}`);
  }
  return JSON.parse(fs.readFileSync(jsonOut, "utf8"));
}

/** Linear fit |π| ≈ a*d + b over packed Merkle depth d. */
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

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const cftOnly = runMeasure(
    "build_measure_longfellow_prove_verify_proof_size.sh",
    CFT_JSON
  );
  const revocation = runMeasure(
    "build_measure_longfellow_prove_verify_revocation_proof_size.sh",
    REVOC_JSON
  );

  const report = {
    meta: { type: "longfellow" },
    cftOnly: {
      circuit: cftOnly.circuit,
      proof: cftOnly.proof,
      publicInputs: cftOnly.publicInputs,
      showMessageIfProofPlusAllPublic: cftOnly.showMessageIfProofPlusAllPublic,
      showMessageIfProofPlusCftOnlyCachedKeys:
        cftOnly.showMessageIfProofPlusCftOnlyCachedKeys,
    },
    withRevocation: {
      circuit: revocation.circuit,
      cftBytes: revocation.cftBytes,
      publicInputsBytes: revocation.publicInputsBytes,
      byScale: revocation.byScale,
      fitVsDepth: fitVsDepth(revocation.byScale),
    },
  };

  const ts = new Date().toISOString().replaceAll(":", "-");
  const summaryTs = path.join(OUT_DIR, `summary_${ts}.json`);
  fs.writeFileSync(summaryTs, JSON.stringify(report, null, 2) + "\n");
  fs.writeFileSync(SUMMARY_JSON, JSON.stringify(report, null, 2) + "\n");
  console.log("\n=== communication-size summary ===");
  console.log(JSON.stringify(report, null, 2));
  console.log(`\nWrote ${SUMMARY_JSON}`);
}

main();
