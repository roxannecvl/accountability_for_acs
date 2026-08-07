#!/usr/bin/env node
"use strict";

/**
 * Zk-friendly: ProveVerify + CFT + packed status-list revocation (Poseidon Merkle).
 *
 * Default: BENCH_N=10, REVOC_LOG2_LIST=12,16,20,24.
 *
 * Timing (aligned with prove-verify / prove-verify-no-cft):
 *   witness = per-show input prep (buildShowInput + Merkle path + write JSON)
 *             + C++ witness calculator
 *   prove   = rapidsnark only
 *   verify  = snarkjs.groth16.verify only (parse outside timer)
 *
 * Env:
 *   REVOC_LOG2_LIST=12,16,20,24
 *   REVOC_BITS_PER_LEAF=253
 *   REVOC_SLOT=14
 *   BENCH_N=10
 *   BENCH_WARMUP=1               discarded full iterations before timed runs
 *   BENCH_VERIFY_WARMUP=0        optional extra snarkjs.verify calls on the warmup
 *                               iter only (default 0; set >0 only if needed)
 *   BENCH_GC_BEFORE_VERIFY=1     optional: force global.gc() before timed verify
 *                               (needs node --expose-gc; default off)
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { buildBabyjub, buildEddsa, buildPoseidon } = require("circomlibjs");

const zkCommon = require("../lib/zk_common");
const codegen = require("./lib/circom_codegen");
const revTree = require("./lib/revocation_tree");
const {
  initCredentialOnce,
  buildShowInput,
  withRevocationIndex,
  computeClaimName,
} = require("../prove-verify/bench_prove_verify.js");

const DEFAULT_LOG2 = [12, 16, 20, 24];

function parseLog2List() {
  const raw = process.env.REVOC_LOG2_LIST ?? process.env.REVOC_LOG2;
  if (!raw) return DEFAULT_LOG2;
  return String(raw)
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n));
}

const REVOC_LOG2_LIST = parseLog2List();
const REVOC_BITS = parseInt(process.env.REVOC_BITS_PER_LEAF ?? "253", 10);
const REVOC_SLOT = parseInt(process.env.REVOC_SLOT ?? "14", 10);
const BENCH_N = parseInt(process.env.BENCH_N ?? "10", 10);
const BENCH_WARMUP = parseInt(process.env.BENCH_WARMUP ?? "1", 10);
const VERIFY_WARMUP = parseInt(process.env.BENCH_VERIFY_WARMUP ?? "0", 10);
const GC_BEFORE_VERIFY = process.env.BENCH_GC_BEFORE_VERIFY === "1";
const VERBOSE = process.argv.includes("--verbose");

const BASE_DIR = __dirname;
const ARTIFACTS_DIR = path.join(BASE_DIR, "artifacts_bench_prove_verify_revocation");

const RAPIDSNARK_BIN = process.env.RAPIDSNARK_BIN || "prover";
const CIRCOM_BIN = process.env.CIRCOM_BIN || process.env.CIRCOM || "circom";
const PTAU = "../powersOfTau/powersOfTau28_hez_final_19.ptau";

const zk = zkCommon.createZkUtils(BASE_DIR);

function randomCredentialIndex(population) {
  const buf = crypto.randomBytes(4);
  return Number(buf.readUInt32BE(0)) % population;
}

function stats(arr) {
  if (!arr.length) return null;
  const sorted = [...arr].sort((a, b) => a - b);
  const avg = arr.reduce((s, x) => s + x, 0) / arr.length;
  return { min: sorted[0], max: sorted[sorted.length - 1], avg };
}

async function benchScale({
  revocLog2,
  credential,
  revClaimName,
  poseidon,
}) {
  const population = 1 << revocLog2;
  const suffix = `_l${revocLog2}`;
  const meta = codegen.writeGeneratedCircuits({
    outDir: BASE_DIR,
    population,
    bitsPerLeaf: REVOC_BITS,
    revocSlot: REVOC_SLOT,
    suffix,
  });

  const circomFile = `./${meta.proveVerifyFile}`;
  const circuitName = path.basename(circomFile, ".circom");
  const outDir = path.join("generated", circuitName);
  fs.mkdirSync(path.join(BASE_DIR, outDir), { recursive: true });

  const r1cs = path.join(outDir, `${circuitName}.r1cs`);
  const zkey = path.join(outDir, `${circuitName}.zkey`);
  const vkey = path.join(outDir, `vkey-${circuitName}.json`);

  const zkPrint = VERBOSE ? zk : { ...zk, section: () => {} };
  const { witnessBin, zkeyFile, vkeyFile } = zkCommon.prepareGroth16(zkPrint, {
    rapidsnarkBin: RAPIDSNARK_BIN,
    circomFile,
    r1csFile: path.relative(BASE_DIR, r1cs),
    ptauFile: PTAU,
    zkeyFile: path.relative(BASE_DIR, zkey),
    vkeyFile: path.relative(BASE_DIR, vkey),
    outDir: path.relative(BASE_DIR, outDir),
    circomBin: CIRCOM_BIN,
  });

  const vkeyAbs = zk.resolvePath(vkeyFile);
  const zkeyAbs = zk.resolvePath(zkeyFile);
  const witnessAbs = zk.resolvePath(witnessBin);
  for (const [label, abs] of [
    ["zkey", zkeyAbs],
    ["vkey", vkeyAbs],
    ["witness generator", witnessAbs],
  ]) {
    if (!fs.existsSync(abs)) {
      throw new Error(
        `Missing ${label} after setup @2^${revocLog2}: ${abs}\n` +
          `Delete generated/${circuitName}/ and retry this scale.`
      );
    }
  }

  const vkeyObj = JSON.parse(fs.readFileSync(vkeyAbs, "utf8"));
  const snarkjs = require("snarkjs");

  const packedTree = revTree.buildPackedRevocationTree(poseidon, population, REVOC_BITS);

  const witnessMs = [];
  const proveMs = [];
  const verifyMs = [];
  const warmupIters = Math.max(0, BENCH_WARMUP);
  const totalIters = BENCH_N + warmupIters;

  console.log(
    `\n── 2^${revocLog2} (depth ${meta.merkleDepth}, N=${population}) ──` +
      `\n  timed=${BENCH_N}` +
      (warmupIters ? ` (+${warmupIters} warmup discarded)` : "") +
      (VERIFY_WARMUP > 0 ? `, verifyWarmup=${VERIFY_WARMUP}` : "")
  );

  for (let i = 0; i < totalIters; i++) {
    const isWarmup = i < warmupIters;
    const iterDir = path.join(
      ARTIFACTS_DIR,
      `${circuitName}_l${revocLog2}_iter_${String(i).padStart(4, "0")}`
    );
    fs.mkdirSync(iterDir, { recursive: true });

    const wtnsRel = path.relative(BASE_DIR, path.join(iterDir, "witness.wtns"));
    const proofRel = path.relative(BASE_DIR, path.join(iterDir, "proof.json"));
    const publicRel = path.relative(BASE_DIR, path.join(iterDir, "public.json"));
    const inputRel = path.relative(BASE_DIR, path.join(iterDir, "input.json"));
    const inputAbs = path.join(iterDir, "input.json");

    // Witness timer = per-show input prep + write + witness bin.
    const t0 = zk.nowNs();
    const credIdx = randomCredentialIndex(population);
    const rev = revTree.proofForPacked({ poseidon, tree: packedTree, credentialIndex: credIdx });

    const cred = withRevocationIndex(credential, REVOC_SLOT, credIdx);
    const base = buildShowInput(cred, credIdx + 1);
    const input = {
      ...base,
      revClaimName: poseidon.F.toString(revClaimName),
      revocationRoot: rev.revocationRoot,
      leafIndex: rev.leafIndex,
      bitIndex: rev.bitIndex,
      leafValue: rev.leafValue,
      pathElements: rev.pathElements,
      pathIndices: rev.pathIndices,
    };
    fs.writeFileSync(inputAbs, JSON.stringify(input, null, 2));

    const wRes = zk.exec(
      `${zkCommon.shellQuote(witnessBin)} ${zkCommon.shellQuote(inputRel)} ${zkCommon.shellQuote(wtnsRel)}`
    );
    const wMs = zk.nsToMs(zk.nowNs() - t0);
    if (!wRes.ok) throw new Error(`witness failed @2^${revocLog2}: ${wRes.stderr || wRes.stdout}`);

    const t1 = zk.nowNs();
    const pRes = zk.exec(
      `${zkCommon.shellQuote(RAPIDSNARK_BIN)} ${zkCommon.shellQuote(zkeyFile)} ${zkCommon.shellQuote(wtnsRel)} ${zkCommon.shellQuote(proofRel)} ${zkCommon.shellQuote(publicRel)}`
    );
    const pMs = zk.nsToMs(zk.nowNs() - t1);
    if (!pRes.ok) {
      const missing = [zkeyFile, wtnsRel].filter((p) => !fs.existsSync(zk.resolvePath(p)));
      const hint = missing.length
        ? ` Missing: ${missing.map((p) => zk.resolvePath(p)).join(", ")}`
        : "";
      throw new Error(`prove failed @2^${revocLog2}: ${pRes.stderr || pRes.stdout || "unknown"}${hint}`);
    }

    const proofObj = JSON.parse(fs.readFileSync(path.join(iterDir, "proof.json"), "utf8"));
    const publicSignals = JSON.parse(fs.readFileSync(path.join(iterDir, "public.json"), "utf8"));

    if (isWarmup && VERIFY_WARMUP > 0) {
      for (let w = 0; w < VERIFY_WARMUP; w++) {
        await snarkjs.groth16.verify(vkeyObj, publicSignals, proofObj);
      }
    }

    if (GC_BEFORE_VERIFY && global.gc) global.gc();

    const t2 = zk.nowNs();
    const ok = await snarkjs.groth16.verify(vkeyObj, publicSignals, proofObj);
    const vMs = zk.nsToMs(zk.nowNs() - t2);
    if (!ok) throw new Error(`verify failed @2^${revocLog2}`);

    if (!isWarmup) {
      witnessMs.push(wMs);
      proveMs.push(pMs);
      verifyMs.push(vMs);
    }

    if (!VERBOSE) {
      const label = isWarmup
        ? `warmup ${i + 1}/${warmupIters}`
        : `${i - warmupIters + 1}/${BENCH_N}`;
      process.stdout.write(
        `  ${label} witness=${wMs.toFixed(0)}ms prove=${pMs.toFixed(0)}ms verify=${vMs.toFixed(0)}ms\n`
      );
    }
  }

  return {
    revocLog2,
    population,
    merkleDepth: meta.merkleDepth,
    witness: stats(witnessMs),
    prove: stats(proveMs),
    verify: stats(verifyMs),
    proverTotal: stats(witnessMs.map((w, i) => w + proveMs[i])),
  };
}

async function main() {
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });

  console.log("Zk-friendly ProveVerify + CFT + packed revocation");
  console.log(`  scales: ${REVOC_LOG2_LIST.map((x) => `2^${x}`).join(", ")}`);
  console.log(
    `  bits/leaf = ${REVOC_BITS}, BENCH_N = ${BENCH_N}` +
      `, warmup = ${BENCH_WARMUP}, verifyWarmup = ${VERIFY_WARMUP}` +
      `, gcBeforeVerify = ${GC_BEFORE_VERIFY}${
        GC_BEFORE_VERIFY && typeof global.gc !== "function"
          ? " (WARNING: no global.gc — start node with --expose-gc)"
          : ""
      }\n`
  );

  const babyJub = await buildBabyjub();
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const cryptoCtx = { babyJub, F: babyJub.F, eddsa, poseidon, prime: poseidon.F.p };
  const credential = initCredentialOnce(cryptoCtx);
  const revClaimName = computeClaimName(cryptoCtx, "revocationIndex");

  const byScale = [];
  for (const revocLog2 of REVOC_LOG2_LIST) {
    byScale.push(
      await benchScale({
        revocLog2,
        credential,
        revClaimName,
        poseidon,
      })
    );
  }

  const summary = {
    meta: {
      type: "zk-friendly",
      revocLog2List: REVOC_LOG2_LIST,
      bitsPerLeaf: REVOC_BITS,
      revocSlot: REVOC_SLOT,
      benchN: BENCH_N,
      warmup: BENCH_WARMUP,
      verifyWarmup: VERIFY_WARMUP,
      gcBeforeVerify: GC_BEFORE_VERIFY,
      gcAvailable: typeof global.gc === "function",
      timestampIso: new Date().toISOString(),
    },
    byScale,
  };

  const ts = new Date().toISOString().replaceAll(":", "-");
  fs.writeFileSync(path.join(ARTIFACTS_DIR, `summary_${ts}.json`), JSON.stringify(summary, null, 2));
  const summaryPath = path.join(ARTIFACTS_DIR, "summary_latest.json");
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

  console.log("\n── Summary (avg prover ms) ──");
  for (const r of byScale) {
    console.log(
      `  2^${r.revocLog2} (depth ${r.merkleDepth})  witness=${r.witness.avg.toFixed(1)}  prove=${r.prove.avg.toFixed(1)}  verify=${r.verify.avg.toFixed(1)}  prover=${r.proverTotal.avg.toFixed(1)}`
    );
  }
  console.log(`\nSummary: ${summaryPath}`);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
