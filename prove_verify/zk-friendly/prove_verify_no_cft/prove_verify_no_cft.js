#!/usr/bin/env node
"use strict";

/**
 * ZK-friendly (Circom + Groth16 / rapidsnark) driver for the "prove + verify"
 * credential proof, **no-CFT** variant: same Poseidon-fold commitment and EdDSA
 * signatures as `../prove_verify/bench_prove_verify.js`, but drops the ID /
 * ElGamal-related inputs and the c1..c4 outputs (5 disclosed slots:
 * 4,5,6,14,15). 6 zero-padding public inputs keep snarkjs' Pippenger window
 * comparable to the CFT variant. Default: 20 measured iterations + 1 warm-up.
 */

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

const zkCommon = require("../lib/zk_common");
const { randomScalarMod, sha256Utf8ToField } = require("../lib/crypto_common");
const { BABYJUB_ORDER } = require("../lib/crypto_babyjub");
const NUM_ATTRS = 32;
const USED_INDICES = [4, 5, 6, 14, 15];

const DEMO_NAME = "prove_verify_no_cft";
const CIRCUIT_CIRCOM = `./${DEMO_NAME}.circom`;
const CIRCUIT_R1CS = `./generated/${DEMO_NAME}.r1cs`;
const GROTH16_PTAU_FILE = "../powersOfTau/powersOfTau28_hez_final_19.ptau";
const ZKEY_FILE = `./generated/circuit-${DEMO_NAME}.zkey`;
const VKEY_FILE = `./generated/vkey-${DEMO_NAME}.json`;
const ARTIFACTS_DIR = `./artifacts_bench_${DEMO_NAME}`;
const RAPIDSNARK_BIN = process.env.RAPIDSNARK_BIN || "prover";
const CIRCOM_BIN = process.env.CIRCOM_BIN || process.env.CIRCOM || "circom";

const N = parseInt(process.env.BENCH_N ?? "10", 10);
const VERBOSE = process.argv.includes("--verbose");
const QUIET = !VERBOSE;
const KEEP_ARTIFACTS = process.argv.includes("--keep-artifacts") || process.env.KEEP_ARTIFACTS === "1";

const zk = zkCommon.createZkUtils(__dirname);
const { ensureDir, writeJson, section } = zk;
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

function buildFreshInput({ eddsa, poseidon, prime }) {
  const now = 1710000000000n;
  const maxBirthDate = now - compute18YearsMs();

  const issuerPrv = crypto.randomBytes(32);
  const issuerPubPoint = eddsa.prv2pub(issuerPrv);
  const issuerPubKey = [eddsa.F.toString(issuerPubPoint[0]), eddsa.F.toString(issuerPubPoint[1])];

  const hwPrv = crypto.randomBytes(32);
  const hwPubPoint = eddsa.prv2pub(hwPrv);
  const hwPk = [eddsa.F.toString(hwPubPoint[0]), eddsa.F.toString(hwPubPoint[1])];

  const m = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const mBig = BigInt(m);

  const birthDate = maxBirthDate - ms(365);
  const validFrom = now - ms(1);
  const validUntil = now + ms(365);

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
  // Slots 0 and 1 (IDx, IDy) are intentionally unused in this benchmark variant.
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
  const sig_R = [eddsa.F.toString(sig.R8[0]), eddsa.F.toString(sig.R8[1])];

  const hwSig = eddsa.signPoseidon(hwPrv, eddsa.F.e(mBig));
  const hwSig_R = [eddsa.F.toString(hwSig.R8[0]), eddsa.F.toString(hwSig.R8[1])];

  const claimNamesStr = claimNames.map((x) => poseidon.F.toString(x));
  const claimValuesStr = claimValues.map((v) => v.toString());

  return {
    issuerPubKey,
    m: mBig.toString(),
    now: now.toString(),
    maxBirthDate: maxBirthDate.toString(),
    bdClaimName: claimNamesStr[4],
    vfClaimName: claimNamesStr[5],
    vuClaimName: claimNamesStr[6],
    hwPkXClaimName: claimNamesStr[14],
    hwPkYClaimName: claimNamesStr[15],
    pad0: "0",
    pad1: "0",
    pad2: "0",
    pad3: "0",
    pad4: "0",
    pad5: "0",
    claimNames: claimNamesStr,
    claimValues: claimValuesStr,
    birthDate: birthDate.toString(),
    validFrom: validFrom.toString(),
    validUntil: validUntil.toString(),
    hwPk,
    sig_R,
    sig_S: sig.S.toString(),
    hwSig_R,
    hwSig_S: hwSig.S.toString(),
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
  if (VERBOSE) console.log("Ready.\n");

  sectionPrint(`Benchmark — ${N} iterations`);
  if (!VERBOSE) {
    console.log(`Iterations: ${N} (+1 warmup discarded)`);
    console.log(`Cleanup after run: ${KEEP_ARTIFACTS ? "disabled (--keep-artifacts)" : "enabled (default)"}`);
  }

  const witnessMs = [];
  const proveMs = [];
  const verifyMs = [];
  let failures = 0;

  const snarkjs = require("snarkjs");
  const vkeyObj = JSON.parse(fs.readFileSync(path.join(__dirname, "generated", `vkey-${DEMO_NAME}.json`), "utf8"));

  const warmupIters = 1;
  const totalIters = N + warmupIters;

  for (let i = 0; i < totalIters; i++) {
    const isWarmup = i < warmupIters;
    const iterDir = path.join(ARTIFACTS_DIR, `iter_${String(i).padStart(4, "0")}`);
    ensureDir(iterDir);

    const inputJson = path.join(iterDir, "input.json");
    const witnessWtns = path.join(iterDir, "witness.wtns");
    const proofJson = path.join(iterDir, "proof.json");
    const publicJson = path.join(iterDir, "public.json");

    const input = buildFreshInput(crypto_ctx);
    writeJson(inputJson, input);

    const tW0 = zk.nowNs();
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
    if (!fs.existsSync(proofJson) || !fs.existsSync(publicJson)) {
      console.error(`  iter ${i}: prove produced no proof/public outputs`);
      failures++;
      continue;
    }

    const tV0 = zk.nowNs();
    const proofObj = JSON.parse(fs.readFileSync(proofJson, "utf8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicJson, "utf8"));
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
      numAttrs: NUM_ATTRS,
      usedAttrs: USED_INDICES.length,
      N,
      timestampIso: new Date().toISOString(),
    },
    results: { successfulIters: successful, failures },
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
    fs.writeFileSync(path.join(ARTIFACTS_DIR, `summary_${ts}.json`), JSON.stringify(summary, null, 2));
    fs.writeFileSync(path.join(ARTIFACTS_DIR, "summary_latest.json"), JSON.stringify(summary, null, 2));
  } catch {}

  if (VERBOSE && successful > 0) {
    printStats("witness", witnessMs);
    printStats("prove", proveMs);
    printStats("verify", verifyMs);
    printStats("prover total", proverTotalMs);
    printStats("full cycle", fullCycleMs);
  }

  if (!KEEP_ARTIFACTS) cleanupArtifactsKeepSummaries(path.join(__dirname, ARTIFACTS_DIR));
  if (!KEEP_ARTIFACTS) cleanupGeneratedOutputs();

  if (!VERBOSE) {
    console.log(
      `Summary written: ${path.join(ARTIFACTS_DIR, "summary_latest.json")}` +
        (KEEP_ARTIFACTS ? " (artifacts kept)" : " (artifacts cleaned)")
    );
  }

  if (failures > 0) process.exit(1);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

