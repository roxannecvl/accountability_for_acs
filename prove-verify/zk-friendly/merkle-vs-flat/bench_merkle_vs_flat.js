#!/usr/bin/env node
"use strict";

// Standalone copy of the Merkle-vs-flat benchmark (no dependency on elGamal_demos/).

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");

const zkCommon = require("../lib/zk_common");
const merkle = require("../lib/poseidon_merkle");
const { sha256Utf8ToField } = require("../lib/crypto_common");

const RAPIDSNARK_BIN = process.env.RAPIDSNARK_BIN || "prover";
const CIRCOM_BIN = process.env.CIRCOM_BIN || process.env.CIRCOM || "circom";
const GROTH16_PTAU_FILE = "../powersOfTau/powersOfTau28_hez_final_19.ptau";

function parseIntListEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => Number(s));
  const ok = parts.filter((x) => Number.isInteger(x) && x > 0);
  return ok.length ? ok : fallback;
}

const TOTAL_ATTRS_LIST = parseIntListEnv("TOTAL_ATTRS", [8, 16, 32, 64]);
const USED_ATTRS_LIST = parseIntListEnv("USED_ATTRS", [1, 2, 4, 8, 16]);
const N = parseInt(process.env.BENCH_N ?? "10", 10);
const VERBOSE = process.argv.includes("--verbose");
// Quiet is the default: only print per-point lines (or recap grids) unless --verbose.
// Keep --quiet as a compatibility no-op.
const QUIET = !VERBOSE;
const CLEAN = process.argv.includes("--clean") || process.env.CLEAN === "1";
const COMPACT = process.argv.includes("--compact");
const KEEP_ARTIFACTS = process.argv.includes("--keep-artifacts") || process.env.KEEP_ARTIFACTS === "1";
// Verifier model:
// - a long-running verifier service with the vkey cached in memory
// - per proof: parse (proof + public signals) + verify

const BASE_DIR = __dirname;
const ARTIFACTS_DIR = path.join(BASE_DIR, "artifacts_bench_merkle_vs_flat");
const GENERATED_DIR = path.join(BASE_DIR, "generated");

const zk = zkCommon.createZkUtils(BASE_DIR);
const zkPrint = VERBOSE ? zk : { ...zk, section: () => {} };

function isoForFilename(d = new Date()) {
  // Example: 2026-05-11T14-22-03Z
  return d.toISOString().replaceAll(":", "-");
}

function ensureCleanDirs() {
  if (CLEAN) {
    try { fs.rmSync(GENERATED_DIR, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(ARTIFACTS_DIR, { recursive: true, force: true }); } catch {}
    try {
      for (const f of fs.readdirSync(BASE_DIR)) {
        if (!f.endsWith(".circom")) continue;
        if (f.startsWith("merkle_t") || f.startsWith("flat_t")) fs.rmSync(path.join(BASE_DIR, f), { force: true });
      }
    } catch {}
  }
  zk.ensureDir("generated");
  zk.ensureDir("artifacts_bench_merkle_vs_flat");
}

function cleanupArtifactsKeepSummaries() {
  // Keep only summary JSONs (they are the only “result” we need after a run).
  try {
    if (!fs.existsSync(ARTIFACTS_DIR)) return;
    for (const entry of fs.readdirSync(ARTIFACTS_DIR, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.startsWith("summary_") && entry.name.endsWith(".json")) continue;
      if (entry.isFile() && entry.name === "summary_latest.json") continue;
      fs.rmSync(path.join(ARTIFACTS_DIR, entry.name), { recursive: true, force: true });
    }
  } catch {}
}

function cleanupGeneratedOutputs() {
  // Remove generated circuits and compiled outputs (can be regenerated from scratch).
  try { fs.rmSync(GENERATED_DIR, { recursive: true, force: true }); } catch {}
  try {
    for (const f of fs.readdirSync(BASE_DIR)) {
      if (!f.endsWith(".circom")) continue;
      if (f.startsWith("merkle_t") || f.startsWith("flat_t")) fs.rmSync(path.join(BASE_DIR, f), { force: true });
    }
  } catch {}
}

function stats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const n = sorted.length;
  const avg = arr.reduce((s, x) => s + x, 0) / n;
  const median = n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[Math.floor(n / 2)];
  const p95 = sorted[Math.floor(n * 0.95)];
  return { min: sorted[0], max: sorted[n - 1], avg, median, p95 };
}
function fmt(ms) { return ms.toFixed(2).padStart(9); }
function printStats(label, arr) {
  if (!arr.length) return;
  const s = stats(arr);
  console.log(
    `${label.padEnd(18)} min=${fmt(s.min)}ms  avg=${fmt(s.avg)}ms  median=${fmt(s.median)}ms  p95=${fmt(s.p95)}ms  max=${fmt(s.max)}ms`
  );
}
function avg(arr) {
  if (!arr.length) return null;
  return arr.reduce((s, x) => s + x, 0) / arr.length;
}

function computeClaimName({ poseidon, prime }, label) {
  const labelScalar = sha256Utf8ToField(label, prime);
  return poseidon([labelScalar]);
}

function randomFieldElement(prime) {
  const buf = crypto.randomBytes(32);
  const x = BigInt("0x" + buf.toString("hex"));
  return x % prime;
}

function writeGeneratedCircom(filePathAbs, code) {
  try {
    const prev = fs.readFileSync(filePathAbs, "utf8");
    if (prev === code) return;
  } catch {}
  fs.writeFileSync(filePathAbs, code, "utf8");
}

function genMerkleCircuit({ totalAttrs, usedAttrs }) {
  const depth = Math.log2(totalAttrs);
  if (!Number.isInteger(depth)) throw new Error(`totalAttrs must be power-of-two, got ${totalAttrs}`);

  const pubInputs = ["root"];
  for (let i = 0; i < usedAttrs; i++) pubInputs.push(`claimName_${i}`);

  const lines = [];
  lines.push("pragma circom 2.0.0;");
  lines.push("");
  lines.push('include "circomlib/circuits/poseidon.circom";');
  lines.push('include "circomlib/circuits/switcher.circom";');
  lines.push("");
  lines.push("template MerkleClaimProof(depth) {");
  lines.push("    signal input claimName;");
  lines.push("    signal input claimValue;");
  lines.push("    signal input pathElements[depth];");
  lines.push("    signal input pathIndices[depth];");
  lines.push("    signal output root;");
  lines.push("");
  lines.push("    component nameHash = Poseidon(1);");
  lines.push("    nameHash.inputs[0] <== claimName;");
  lines.push("");
  lines.push("    component leafHash = Poseidon(2);");
  lines.push("    leafHash.inputs[0] <== nameHash.out;");
  lines.push("    leafHash.inputs[1] <== claimValue;");
  lines.push("");
  lines.push("    component hashers[depth];");
  lines.push("    component switchers[depth];");
  lines.push("    signal currentHash[depth + 1];");
  lines.push("    currentHash[0] <== leafHash.out;");
  lines.push("");
  lines.push("    for (var i = 0; i < depth; i++) {");
  lines.push("        switchers[i] = Switcher();");
  lines.push("        switchers[i].sel <== pathIndices[i];");
  lines.push("        switchers[i].L   <== currentHash[i];");
  lines.push("        switchers[i].R   <== pathElements[i];");
  lines.push("");
  lines.push("        hashers[i] = Poseidon(2);");
  lines.push("        hashers[i].inputs[0] <== switchers[i].outL;");
  lines.push("        hashers[i].inputs[1] <== switchers[i].outR;");
  lines.push("");
  lines.push("        currentHash[i + 1] <== hashers[i].out;");
  lines.push("    }");
  lines.push("");
  lines.push("    root <== currentHash[depth];");
  lines.push("}");
  lines.push("");
  lines.push("template CredentialMerkleBench() {");
  lines.push("    signal input root;");
  lines.push("");
  for (let i = 0; i < usedAttrs; i++) {
    lines.push(`    signal input claimName_${i};`);
    lines.push(`    signal input claimValue_${i};`);
    lines.push(`    signal input pathElements_${i}[${depth}];`);
    lines.push(`    signal input pathIndices_${i}[${depth}];`);
    lines.push("");
  }
  lines.push("    signal output ok;");
  lines.push("");
  lines.push(`    component proofs[${usedAttrs}];`);
  for (let i = 0; i < usedAttrs; i++) {
    lines.push(`    proofs[${i}] = MerkleClaimProof(${depth});`);
    lines.push(`    proofs[${i}].claimName <== claimName_${i};`);
    lines.push(`    proofs[${i}].claimValue <== claimValue_${i};`);
    lines.push(`    for (var d = 0; d < ${depth}; d++) {`);
    lines.push(`        proofs[${i}].pathElements[d] <== pathElements_${i}[d];`);
    lines.push(`        proofs[${i}].pathIndices[d]  <== pathIndices_${i}[d];`);
    lines.push("    }");
    lines.push(`    proofs[${i}].root === root;`);
    lines.push("");
  }
  lines.push("    ok <== 1;");
  lines.push("}");
  lines.push("");
  lines.push(`component main {public [${pubInputs.join(", ")}]} = CredentialMerkleBench();`);
  lines.push("");
  return lines.join("\n");
}

function genFlatCircuit({ totalAttrs, usedAttrs }) {
  // acc_{i+1} = Poseidon(acc_i, name_i, value_i)
  const pubInputs = ["flatHash"];
  for (let i = 0; i < usedAttrs; i++) {
    pubInputs.push(`revealName_${i}`);
    pubInputs.push(`revealValue_${i}`);
  }

  const lines = [];
  lines.push("pragma circom 2.0.0;");
  lines.push("");
  lines.push('include "circomlib/circuits/poseidon.circom";');
  lines.push("");
  lines.push("template CredentialFlatBench() {");
  lines.push("    signal input flatHash;");
  lines.push("");
  lines.push(`    signal input claimNames[${totalAttrs}];`);
  lines.push(`    signal input claimValues[${totalAttrs}];`);
  lines.push("");
  for (let i = 0; i < usedAttrs; i++) {
    lines.push(`    signal input revealName_${i};`);
    lines.push(`    signal input revealValue_${i};`);
  }
  lines.push("");
  lines.push("    signal output ok;");
  lines.push("");
  for (let i = 0; i < usedAttrs; i++) {
    lines.push(`    revealName_${i} === claimNames[${i}];`);
    lines.push(`    revealValue_${i} === claimValues[${i}];`);
  }
  lines.push("");
  lines.push(`    signal acc[${totalAttrs} + 1];`);
  lines.push("    acc[0] <== 0;");
  lines.push(`    component mix[${totalAttrs}];`);
  lines.push(`    for (var i = 0; i < ${totalAttrs}; i++) {`);
  lines.push("        mix[i] = Poseidon(3);");
  lines.push("        mix[i].inputs[0] <== acc[i];");
  lines.push("        mix[i].inputs[1] <== claimNames[i];");
  lines.push("        mix[i].inputs[2] <== claimValues[i];");
  lines.push("        acc[i + 1] <== mix[i].out;");
  lines.push("    }");
  lines.push("");
  lines.push(`    flatHash === acc[${totalAttrs}];`);
  lines.push("");
  lines.push("    ok <== 1;");
  lines.push("}");
  lines.push("");
  lines.push(`component main {public [${pubInputs.join(", ")}]} = CredentialFlatBench();`);
  lines.push("");
  return lines.join("\n");
}

async function buildCommonCrypto() {
  const poseidon = await buildPoseidon();
  const prime = poseidon.F.p;
  return { poseidon, prime };
}

function buildFreshCredential({ poseidon, prime }, totalAttrs) {
  const labels = Array.from({ length: totalAttrs }, (_, i) => `attr_${i}`);
  const claimNames = labels.map((l) => computeClaimName({ poseidon, prime }, l));
  const claimValues = Array.from({ length: totalAttrs }, () => randomFieldElement(prime));
  return { claimNames, claimValues };
}

function buildMerkleInput({ poseidon, prime }, { totalAttrs, usedAttrs }) {
  const { claimNames, claimValues } = buildFreshCredential({ poseidon, prime }, totalAttrs);
  const depth = Math.log2(totalAttrs);

  const leaves = claimValues.map((v, i) =>
    merkle.buildLeaf({ poseidon, claimName: claimNames[i], claimValue: poseidon.F.e(v) })
  );
  const root = merkle.buildMerkleRoot({ poseidon, leaves });

  const input = { root: poseidon.F.toString(root) };
  for (let i = 0; i < usedAttrs; i++) {
    const proof = merkle.getMerkleProof({ poseidon, leaves, index: i, depth });
    input[`claimName_${i}`] = poseidon.F.toString(claimNames[i]);
    input[`claimValue_${i}`] = claimValues[i].toString();
    input[`pathElements_${i}`] = proof.pathElements.map((x) => poseidon.F.toString(x));
    input[`pathIndices_${i}`] = proof.pathIndices;
  }
  return input;
}

function buildFlatInput({ poseidon, prime }, { totalAttrs, usedAttrs }) {
  const { claimNames, claimValues } = buildFreshCredential({ poseidon, prime }, totalAttrs);

  let acc = poseidon.F.e(0n);
  for (let i = 0; i < totalAttrs; i++) {
    acc = poseidon([acc, claimNames[i], poseidon.F.e(claimValues[i])]);
  }

  const input = {
    flatHash: poseidon.F.toString(acc),
    claimNames: claimNames.map((x) => poseidon.F.toString(x)),
    claimValues: claimValues.map((x) => x.toString()),
  };
  for (let i = 0; i < usedAttrs; i++) {
    input[`revealName_${i}`] = poseidon.F.toString(claimNames[i]);
    input[`revealValue_${i}`] = claimValues[i].toString();
  }
  return input;
}

async function benchOneCircuit({ label, circomRelPath, outDirRel, buildInput }) {
  const circuitName = circomRelPath.replace(/\.circom$/i, "");
  const CIRCUIT_R1CS = path.join(outDirRel, `${circuitName}.r1cs`);
  const ZKEY_FILE = path.join(outDirRel, `circuit-${label}.zkey`);
  const VKEY_FILE = path.join(outDirRel, `vkey-${label}.json`);

  const { witnessBin: cppWitnessBin } = zkCommon.prepareGroth16(zkPrint, {
    rapidsnarkBin: RAPIDSNARK_BIN,
    circomFile: circomRelPath,
    r1csFile: CIRCUIT_R1CS,
    ptauFile: GROTH16_PTAU_FILE,
    zkeyFile: ZKEY_FILE,
    vkeyFile: VKEY_FILE,
    outDir: outDirRel,
    circomBin: CIRCOM_BIN,
  });

  const witnessMs = [];
  const proveMs = [];
  // Verifier timing includes JSON parse + verify (service receives proof/signals).
  const verifyMs = [];
  let failures = 0;

  const snarkjs = require("snarkjs");
  const vkeyObj = JSON.parse(fs.readFileSync(path.join(BASE_DIR, VKEY_FILE), "utf8"));

  const warmupIters = 1;
  const totalIters = N + warmupIters;

  for (let i = 0; i < totalIters; i++) {
    const caseDir = path.join(ARTIFACTS_DIR, label, `iter_${String(i).padStart(4, "0")}`);
    fs.mkdirSync(caseDir, { recursive: true });
    const inputJson = path.join(caseDir, "input.json");
    const witnessWtns = path.join(caseDir, "witness.wtns");
    const proofJson = path.join(caseDir, "proof.json");
    const publicJson = path.join(caseDir, "public.json");

    fs.writeFileSync(inputJson, JSON.stringify(buildInput(), null, 2));

    const tW0 = zk.nowNs();
    const wRes = zk.exec(`${cppWitnessBin} ${inputJson} ${witnessWtns}`);
    const wMs = zk.nsToMs(zk.nowNs() - tW0);
    if (!wRes.ok) {
      failures++;
      if (!QUIET && !COMPACT) process.stdout.write(`    iter ${i}: witness FAILED\n`);
      continue;
    }

    const tP0 = zk.nowNs();
    const pRes = zk.exec(`${RAPIDSNARK_BIN} ${ZKEY_FILE} ${witnessWtns} ${proofJson} ${publicJson}`);
    const pMs = zk.nsToMs(zk.nowNs() - tP0);
    if (!pRes.ok) {
      failures++;
      if (!QUIET && !COMPACT) process.stdout.write(`    iter ${i}: prove FAILED\n`);
      continue;
    }

    const isWarmup = i < warmupIters;

    // In-process verify: time includes JSON parse + verify
    const tV0 = zk.nowNs();
    const proofObj = JSON.parse(fs.readFileSync(proofJson, "utf8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicJson, "utf8"));
    const ok = await snarkjs.groth16.verify(vkeyObj, publicSignals, proofObj);
    const vMs = zk.nsToMs(zk.nowNs() - tV0);
    if (!ok) {
      failures++;
      if (!QUIET && !COMPACT) process.stdout.write(`    iter ${i}: verify (inprocess) FAILED\n`);
      continue;
    }

    if (!isWarmup) {
      witnessMs.push(wMs);
      proveMs.push(pMs);
      verifyMs.push(vMs);
    }

    // (verbose per-iteration printing is disabled in this standalone benchmark; use --compact for progress)
  }

  return { witnessMs, proveMs, verifyMs, failures };
}

function cellStr({ avgProverMs, avgVerifyMs }) {
  const p = avgProverMs == null ? "" : `${avgProverMs.toFixed(0)}`;
  const v = avgVerifyMs == null ? "" : `${avgVerifyMs.toFixed(0)}`;
  return p && v ? `${p}/${v}` : "";
}

function printRecapGrid(title, resultsByTotalAndUsed, totals, useds) {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`  ${title}`);
  console.log("  cell = avgProverMs/avgVerifyMs (prover = witness+prove)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const colW = 12;
  const header = ["total\\used".padEnd(colW), ...useds.map((u) => String(u).padStart(colW))].join("");
  console.log(header);
  console.log("-".repeat(header.length));

  for (const t of totals) {
    const row = [String(t).padEnd(colW)];
    for (const u of useds) {
      const cell = resultsByTotalAndUsed?.[t]?.[u];
      row.push((cell ? cellStr(cell) : "").padStart(colW));
    }
    console.log(row.join(""));
  }
}

async function main() {
  ensureCleanDirs();

  if (VERBOSE) zk.section("Initialising crypto primitives");
  const cryptoCtx = await buildCommonCrypto();
  if (VERBOSE) console.log("Ready.\n");

  // Always print a short benchmark header in quiet mode too.
  if (!VERBOSE) {
    console.log(`Iterations per point: ${N}`);
    console.log(`Totals: ${TOTAL_ATTRS_LIST.join(", ")}`);
    console.log(`Used:   ${USED_ATTRS_LIST.join(", ")}`);
    console.log(`Cleanup after run: ${KEEP_ARTIFACTS ? "disabled (--keep-artifacts)" : "enabled (default)"}`);
    console.log("");
  }

  if (!COMPACT) {
    if (VERBOSE) {
      zk.section("Benchmark sweep");
      console.log(`Iterations per point: ${N}`);
      console.log(`Totals: ${TOTAL_ATTRS_LIST.join(", ")}`);
      console.log(`Used:   ${USED_ATTRS_LIST.join(", ")}\n`);
      if (CLEAN) console.log("Clean:  enabled (--clean / CLEAN=1)\n");
    }
  }

  const summary = {
    meta: {
      type: "zk-friendly",
      N,
      totals: TOTAL_ATTRS_LIST,
      used: USED_ATTRS_LIST,
      timestampIso: new Date().toISOString(),
    },
    merkle: {},
    flat: {},
  };

  for (const totalAttrs of TOTAL_ATTRS_LIST) {
    for (const usedAttrs of USED_ATTRS_LIST) {
      if (usedAttrs > totalAttrs) continue;

      if (!COMPACT) {
        if (VERBOSE) {
          console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
          console.log(`  totalAttrs=${totalAttrs}  usedAttrs=${usedAttrs}`);
          console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
      }

      const merkleLabel = `merkle_t${totalAttrs}_u${usedAttrs}`;
      const flatLabel = `flat_t${totalAttrs}_u${usedAttrs}`;

      const merkleCircomAbs = path.join(BASE_DIR, `${merkleLabel}.circom`);
      const flatCircomAbs = path.join(BASE_DIR, `${flatLabel}.circom`);
      writeGeneratedCircom(merkleCircomAbs, genMerkleCircuit({ totalAttrs, usedAttrs }));
      writeGeneratedCircom(flatCircomAbs, genFlatCircuit({ totalAttrs, usedAttrs }));

      if (COMPACT || !VERBOSE) console.log(`total=${totalAttrs} used=${usedAttrs} mode=merkle`);
      else if (VERBOSE) console.log("\n  Merkle root (public root; prove inclusion for used attrs)");

      const merkleRes = await benchOneCircuit({
        label: merkleLabel,
        circomRelPath: path.basename(merkleCircomAbs),
        outDirRel: "generated",
        buildInput: () => buildMerkleInput(cryptoCtx, { totalAttrs, usedAttrs }),
      });

      if (VERBOSE && !COMPACT) {
        printStats("witness", merkleRes.witnessMs);
        printStats("prove", merkleRes.proveMs);
        printStats("verify", merkleRes.verifyMs);
      }

      const merkleAvgWitness = avg(merkleRes.witnessMs);
      const merkleAvgProve = avg(merkleRes.proveMs);
      const merkleAvgVerify = avg(merkleRes.verifyMs);
      const merkleAvgProver = merkleAvgWitness != null && merkleAvgProve != null ? merkleAvgWitness + merkleAvgProve : null;
      summary.merkle[totalAttrs] ??= {};
      summary.merkle[totalAttrs][usedAttrs] = {
        avgWitnessMs: merkleAvgWitness,
        avgProveMs: merkleAvgProve,
        avgProverMs: merkleAvgProver,
        avgVerifyMs: merkleAvgVerify,
        successfulIters: merkleRes.witnessMs.length,
      };

      if (COMPACT || !VERBOSE) console.log(`total=${totalAttrs} used=${usedAttrs} mode=flat`);
      else if (VERBOSE) console.log("\n  Flat hash (public flatHash over all attrs; reveal used attrs)");

      const flatRes = await benchOneCircuit({
        label: flatLabel,
        circomRelPath: path.basename(flatCircomAbs),
        outDirRel: "generated",
        buildInput: () => buildFlatInput(cryptoCtx, { totalAttrs, usedAttrs }),
      });

      if (VERBOSE && !COMPACT) {
        printStats("witness", flatRes.witnessMs);
        printStats("prove", flatRes.proveMs);
        printStats("verify", flatRes.verifyMs);
      }

      const flatAvgWitness = avg(flatRes.witnessMs);
      const flatAvgProve = avg(flatRes.proveMs);
      const flatAvgVerify = avg(flatRes.verifyMs);
      const flatAvgProver = flatAvgWitness != null && flatAvgProve != null ? flatAvgWitness + flatAvgProve : null;
      summary.flat[totalAttrs] ??= {};
      summary.flat[totalAttrs][usedAttrs] = {
        avgWitnessMs: flatAvgWitness,
        avgProveMs: flatAvgProve,
        avgProverMs: flatAvgProver,
        avgVerifyMs: flatAvgVerify,
        successfulIters: flatRes.witnessMs.length,
      };
    }
  }

  try {
    const ts = isoForFilename();
    const summaryRun = `summary_${ts}.json`;
    fs.writeFileSync(path.join(ARTIFACTS_DIR, summaryRun), JSON.stringify(summary, null, 2));
    fs.writeFileSync(path.join(ARTIFACTS_DIR, "summary_latest.json"), JSON.stringify(summary, null, 2));
  } catch {}

  printRecapGrid("Recap — Flat hash", summary.flat, TOTAL_ATTRS_LIST, USED_ATTRS_LIST);
  printRecapGrid("Recap — Merkle", summary.merkle, TOTAL_ATTRS_LIST, USED_ATTRS_LIST);

  if (!KEEP_ARTIFACTS) {
    cleanupArtifactsKeepSummaries();
    cleanupGeneratedOutputs();
  }

  // In-process verification (snarkjs/ffjavascript) may leave worker threads alive.
  // Exit explicitly so the benchmark terminates after printing recaps.
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

