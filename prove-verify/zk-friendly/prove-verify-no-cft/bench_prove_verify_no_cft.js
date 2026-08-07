#!/usr/bin/env node
"use strict";

/**
 * Age-check presentation without CFT (baseline for accountability overhead).
 * Verify timing: Groth16 check only (vkey cached; proof/public parsed outside the timer).
 * Witness timing: per-show input refresh + circom witness calculator (issuance prep is once, untracked).
 */

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

const SHARED = path.join(__dirname, "..");
const zkCommon = require(path.join(SHARED, "lib/zk_common"));
const { randomScalarMod, sha256Utf8ToField } = require(path.join(SHARED, "lib/crypto_common"));
const { BABYJUB_ORDER } = require(path.join(SHARED, "lib/crypto_babyjub"));
const NUM_ATTRS = 32;
const USED_INDICES = [4, 5, 6, 14, 15];

const DEMO_NAME = "prove_verify_no_cft";
const CIRCUIT_CIRCOM = "./prove_verify_no_cft.circom";
const CIRCUIT_R1CS = "./generated/prove_verify_no_cft.r1cs";
const GROTH16_PTAU_FILE = path.join(SHARED, "powersOfTau/powersOfTau28_hez_final_19.ptau");
const ZKEY_FILE = "./generated/circuit-prove_verify_no_cft.zkey";
const VKEY_FILE = "./generated/vkey-prove_verify_no_cft.json";
const ARTIFACTS_DIR = path.join(__dirname, "artifacts_bench_prove_verify_no_cft");
const RAPIDSNARK_BIN = process.env.RAPIDSNARK_BIN || "prover";
const CIRCOM_BIN = process.env.CIRCOM_BIN || process.env.CIRCOM || "circom";

const N = parseInt(process.env.BENCH_N ?? "10", 10);
const BENCH_WARMUP = parseInt(process.env.BENCH_WARMUP ?? "1", 10);
const VERIFY_WARMUP = parseInt(process.env.BENCH_VERIFY_WARMUP ?? "0", 10);
const VERBOSE = process.argv.includes("--verbose");
const QUIET = !VERBOSE;
const KEEP_ARTIFACTS = process.argv.includes("--keep-artifacts") || process.env.KEEP_ARTIFACTS === "1";

const zk = zkCommon.createZkUtils(__dirname);
const { ensureDir, writeJson, section, resolvePath } = zk;
const sectionPrint = VERBOSE ? section : () => {};

function isoForFilename(d = new Date()) {
  return d.toISOString().replaceAll(":", "-");
}

function cleanupArtifactsKeepSummaries(artifactsDirAbs) {
  try {
    if (!fs.existsSync(artifactsDirAbs)) return;
    for (const entry of fs.readdirSync(artifactsDirAbs, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.startsWith("summary_") && entry.name.endsWith(".json")) continue;
      if (entry.isFile() && entry.name === "summary_latest.json") continue;
      fs.rmSync(path.join(artifactsDirAbs, entry.name), { recursive: true, force: true });
    }
  } catch {}
}

function cleanupGeneratedOutputs() {
  try {
    fs.rmSync(path.join(__dirname, "generated"), { recursive: true, force: true });
  } catch {}
}

function ms(days) {
  return BigInt(days) * 24n * 60n * 60n * 1000n;
}
function compute18YearsMs() {
  return (18n * 36525n * 24n * 60n * 60n * 1000n) / 100n;
}

function computeClaimName({ poseidon, prime }, label) {
  const labelScalar = sha256Utf8ToField(label, prime);
  return poseidon([labelScalar]);
}
function computeClaimValue({ prime }, value) {
  if (typeof value === "bigint") return value % prime;
  if (typeof value === "number") return BigInt(value) % prime;
  if (typeof value === "string") return sha256Utf8ToField(value, prime);
  throw new Error(`Unsupported type: ${typeof value}`);
}

function initCredentialOnce({ eddsa, poseidon, prime }) {
  const baseNow = 1710000000000n;
  const maxBirthDate = baseNow - compute18YearsMs();

  const issuerPrv = crypto.randomBytes(32);
  const issuerPubPoint = eddsa.prv2pub(issuerPrv);
  const issuerPubKey = [eddsa.F.toString(issuerPubPoint[0]), eddsa.F.toString(issuerPubPoint[1])];

  const hwPrv = crypto.randomBytes(32);
  const hwPubPoint = eddsa.prv2pub(hwPrv);
  const hwPk = [eddsa.F.toString(hwPubPoint[0]), eddsa.F.toString(hwPubPoint[1])];

  const m = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const mBig = BigInt(m);

  const birthDate = maxBirthDate - ms(365);
  const validFrom = baseNow - ms(1);
  const validUntil = baseNow + ms(365);

  const labels = [
    "IDx",
    "IDy",
    "name",
    "familyName",
    "birthDate",
    "validFrom",
    "validUntil",
    "addressStreet",
    "addressNumber",
    "addressLocalityNumber",
    "addressCity",
    "addressCanton",
    "addressCountry",
    "cantonOfOrigin",
    "hwPkX",
    "hwPkY",
    "attr_16",
    "attr_17",
    "attr_18",
    "attr_19",
    "attr_20",
    "attr_21",
    "attr_22",
    "attr_23",
    "attr_24",
    "attr_25",
    "attr_26",
    "attr_27",
    "attr_28",
    "attr_29",
    "attr_30",
    "attr_31",
  ];
  const claimNames = labels.map((l) => computeClaimName({ poseidon, prime }, l));
  const claimValues = new Array(NUM_ATTRS).fill(0n);
  claimValues[2] = computeClaimValue({ prime }, "Alice");
  claimValues[3] = computeClaimValue({ prime }, "Doe");
  claimValues[4] = birthDate;
  claimValues[5] = validFrom;
  claimValues[6] = validUntil;
  claimValues[7] = computeClaimValue({ prime }, "Main Street");
  claimValues[8] = 12n;
  claimValues[9] = 1000n;
  claimValues[10] = computeClaimValue({ prime }, "Lausanne");
  claimValues[11] = computeClaimValue({ prime }, "VD");
  claimValues[12] = computeClaimValue({ prime }, "CH");
  claimValues[13] = computeClaimValue({ prime }, "VD");
  claimValues[14] = BigInt(hwPk[0]);
  claimValues[15] = BigInt(hwPk[1]);

  let acc = poseidon.F.e(0n);
  for (let i = 0; i < NUM_ATTRS; i++) {
    acc = poseidon([acc, claimNames[i], poseidon.F.e(claimValues[i])]);
  }
  const sig = eddsa.signPoseidon(issuerPrv, acc);
  const hwSig = eddsa.signPoseidon(hwPrv, eddsa.F.e(mBig));

  const claimNamesStr = claimNames.map((x) => poseidon.F.toString(x));
  const claimValuesStr = claimValues.map((v) => v.toString());

  return {
    baseNow,
    maxBirthDate,
    issuerPubKey,
    m: mBig.toString(),
    claimNamesStr,
    claimValuesStr,
    birthDate,
    validFrom,
    validUntil,
    hwPk,
    sig_R: [eddsa.F.toString(sig.R8[0]), eddsa.F.toString(sig.R8[1])],
    sig_S: sig.S.toString(),
    hwSig_R: [eddsa.F.toString(hwSig.R8[0]), eddsa.F.toString(hwSig.R8[1])],
    hwSig_S: hwSig.S.toString(),
  };
}

function buildShowInput(cred, showIndex) {
  const now = cred.baseNow + BigInt(showIndex);
  return {
    issuerPubKey: cred.issuerPubKey,
    m: cred.m,
    now: now.toString(),
    maxBirthDate: cred.maxBirthDate.toString(),
    bdClaimName: cred.claimNamesStr[4],
    vfClaimName: cred.claimNamesStr[5],
    vuClaimName: cred.claimNamesStr[6],
    hwPkXClaimName: cred.claimNamesStr[14],
    hwPkYClaimName: cred.claimNamesStr[15],
    pad0: "0",
    pad1: "0",
    pad2: "0",
    pad3: "0",
    pad4: "0",
    pad5: "0",
    claimNames: cred.claimNamesStr,
    claimValues: cred.claimValuesStr,
    birthDate: cred.birthDate.toString(),
    validFrom: cred.validFrom.toString(),
    validUntil: cred.validUntil.toString(),
    hwPk: cred.hwPk,
    sig_R: cred.sig_R,
    sig_S: cred.sig_S,
    hwSig_R: cred.hwSig_R,
    hwSig_S: cred.hwSig_S,
  };
}

function stats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const n = sorted.length;
  const avg = arr.reduce((s, x) => s + x, 0) / n;
  const median = n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[Math.floor(n / 2)];
  const p95 = sorted[Math.floor(n * 0.95)];
  return { min: sorted[0], max: sorted[n - 1], avg, median, p95 };
}
function fmt(ms_) {
  return ms_.toFixed(2).padStart(9);
}
function printStats(label, arr) {
  if (!arr.length) return;
  const s = stats(arr);
  console.log(
    `${label.padEnd(16)} min=${fmt(s.min)}ms  avg=${fmt(s.avg)}ms  median=${fmt(s.median)}ms  p95=${fmt(s.p95)}ms  max=${fmt(s.max)}ms`
  );
}
function statsForSummary(arr) {
  if (!arr.length) return null;
  const s = stats(arr);
  return { minMs: s.min, maxMs: s.max, avgMs: s.avg, medianMs: s.median, p95Ms: s.p95 };
}

async function main() {
  ensureDir(ARTIFACTS_DIR);
  ensureDir("./generated");

  const zkPrint = VERBOSE ? zk : { ...zk, section: () => {} };
  const { witnessBin: cppWitnessBin } = zkCommon.prepareGroth16(zkPrint, {
    rapidsnarkBin: RAPIDSNARK_BIN,
    circomFile: CIRCUIT_CIRCOM,
    r1csFile: CIRCUIT_R1CS,
    ptauFile: GROTH16_PTAU_FILE,
    zkeyFile: ZKEY_FILE,
    vkeyFile: VKEY_FILE,
    outDir: "./generated",
    circomBin: CIRCOM_BIN,
  });

  sectionPrint("Initialising crypto primitives");
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const prime = poseidon.F.p;
  const crypto_ctx = { eddsa, poseidon, prime };
  const credential = initCredentialOnce(crypto_ctx);
  if (VERBOSE) console.log("Ready.\n");

  sectionPrint(`Benchmark — ${N} iterations`);
  const warmupIters = Math.max(0, BENCH_WARMUP);
  const totalIters = N + warmupIters;
  if (!VERBOSE) {
    console.log(`Iterations: ${N}` + (warmupIters ? ` (+${warmupIters} warmup discarded)` : ""));
    console.log(`Cleanup after run: ${KEEP_ARTIFACTS ? "disabled (--keep-artifacts)" : "enabled (default)"}`);
  }

  const witnessMs = [];
  const proveMs = [];
  const verifyMs = [];
  let failures = 0;

  const snarkjs = require("snarkjs");
  const vkeyObj = JSON.parse(fs.readFileSync(path.join(__dirname, "generated", `vkey-${DEMO_NAME}.json`), "utf8"));

  for (let i = 0; i < totalIters; i++) {
    const isWarmup = i < warmupIters;
    const iterDir = path.join(ARTIFACTS_DIR, `iter_${String(i).padStart(4, "0")}`);
    ensureDir(iterDir);

    const inputJson = path.join(iterDir, "input.json");
    const witnessWtns = path.join(iterDir, "witness.wtns");
    const proofJson = path.join(iterDir, "proof.json");
    const publicJson = path.join(iterDir, "public.json");

    const tW0 = zk.nowNs();
    const input = buildShowInput(credential, i);
    writeJson(inputJson, input);
    const wRes = zk.exec(`${cppWitnessBin} ${inputJson} ${witnessWtns}`);
    const wMs = zk.nsToMs(zk.nowNs() - tW0);
    if (!wRes.ok) {
      console.error(`  iter ${i}: witness FAILED`);
      failures++;
      continue;
    }

    const tP0 = zk.nowNs();
    const pRes = zk.exec(`${RAPIDSNARK_BIN} ${ZKEY_FILE} ${witnessWtns} ${proofJson} ${publicJson}`);
    const pMs = zk.nsToMs(zk.nowNs() - tP0);
    if (!pRes.ok) {
      console.error(`  iter ${i}: prove FAILED`);
      failures++;
      continue;
    }
    const proofAbs = resolvePath(proofJson);
    const publicAbs = resolvePath(publicJson);
    if (!fs.existsSync(proofAbs) || !fs.existsSync(publicAbs)) {
      console.error(`  iter ${i}: prove produced no proof/public outputs`);
      if (VERBOSE && (pRes.stderr || pRes.stdout)) {
        console.error(pRes.stderr || pRes.stdout);
      }
      failures++;
      continue;
    }

    const proofObj = JSON.parse(fs.readFileSync(proofAbs, "utf8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicAbs, "utf8"));

    if (isWarmup && VERIFY_WARMUP > 0) {
      for (let w = 0; w < VERIFY_WARMUP; w++) {
        await snarkjs.groth16.verify(vkeyObj, publicSignals, proofObj);
      }
    }

    if (process.env.BENCH_GC_BEFORE_VERIFY === "1" && global.gc) global.gc();

    const tV0 = zk.nowNs();
    const ok = await snarkjs.groth16.verify(vkeyObj, publicSignals, proofObj);
    const vMs = zk.nsToMs(zk.nowNs() - tV0);
    if (!ok) {
      console.error(`  iter ${i}: verify (inprocess) FAILED`);
      failures++;
      continue;
    }

    if (!isWarmup) {
      witnessMs.push(wMs);
      proveMs.push(pMs);
      verifyMs.push(vMs);
    }

    const total = wMs + pMs + vMs;
    if (!QUIET && !isWarmup) {
      const shownIter = `${String(i - warmupIters + 1).padStart(3)}/${N}`;
      process.stdout.write(
        `  [${shownIter}] witness=${wMs.toFixed(0)}ms  prove=${pMs.toFixed(0)}ms  verify=${vMs.toFixed(0)}ms  total=${total.toFixed(0)}ms\n`
      );
    }
  }

  const successful = witnessMs.length;

  const proverTotalMs = witnessMs.map((w, i) => w + proveMs[i]);
  const fullCycleMs = witnessMs.map((w, i) => w + proveMs[i] + verifyMs[i]);

  const summary = {
    meta: {
      type: "zk-friendly",
      variant: "prove_verify_no_cft",
      N,
      credentialMode: "init_once_per_show_refresh",
      timestampIso: new Date().toISOString(),
    },
    results: { successfulIters: successful },
    avgMs: {
      witness: successful ? witnessMs.reduce((s, x) => s + x, 0) / successful : null,
      prove: successful ? proveMs.reduce((s, x) => s + x, 0) / successful : null,
      verify: successful ? verifyMs.reduce((s, x) => s + x, 0) / successful : null,
    },
    statsMs: {
      witness: statsForSummary(witnessMs),
      prove: statsForSummary(proveMs),
      verify: statsForSummary(verifyMs),
      proverTotal: statsForSummary(proverTotalMs),
      fullCycle: statsForSummary(fullCycleMs),
    },
  };

  try {
    const ts = isoForFilename();
    fs.writeFileSync(path.join(resolvePath(ARTIFACTS_DIR), `summary_${ts}.json`), JSON.stringify(summary, null, 2));
    fs.writeFileSync(path.join(resolvePath(ARTIFACTS_DIR), "summary_latest.json"), JSON.stringify(summary, null, 2));
  } catch {}

  if (VERBOSE && successful > 0) {
    printStats("witness", witnessMs);
    printStats("prove", proveMs);
    printStats("verify", verifyMs);
    printStats("prover total", proverTotalMs);
    printStats("full cycle", fullCycleMs);
  }

  if (!KEEP_ARTIFACTS) cleanupArtifactsKeepSummaries(resolvePath(ARTIFACTS_DIR));
  if (!KEEP_ARTIFACTS) cleanupGeneratedOutputs();

  if (!VERBOSE) {
    console.log(
      `Summary written: ${path.join(resolvePath(ARTIFACTS_DIR), "summary_latest.json")}` +
        (KEEP_ARTIFACTS ? " (artifacts kept)" : " (artifacts cleaned)")
    );
    if (successful > 0 && summary.statsMs.verify) {
      console.log(
        `  verify median: ${summary.statsMs.verify.medianMs.toFixed(1)} ms` +
          ` (max ${summary.statsMs.verify.maxMs.toFixed(1)} ms — occasional GC spikes; use median for small BENCH_N)`
      );
    }
  }

  if (failures > 0) process.exit(1);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

