#!/usr/bin/env node
"use strict";

/**
 * flat32 v2: C4 = EdDSA(Poseidon(t, r2·pk)) under cred IDu; no separate hw claim.
 * Verify timing: Groth16 check only (vkey cached; proof/public parsed outside the timer).
 * Witness timing: per-show input refresh + circom witness calculator (issuance prep is once, untracked).
 */

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { buildBabyjub, buildEddsa, buildPoseidon } = require("circomlibjs");

const zkCommon = require("../lib/zk_common");
const { randomScalarMod, sha256Utf8ToField, mod } = require("../lib/crypto_common");
const { BABYJUB_ORDER } = require("../lib/crypto_babyjub");
const NUM_ATTRS = 32;

const DEMO_NAME = "prove_verify";
const CIRCUIT_CIRCOM = "./prove_verify.circom";
const CIRCUIT_R1CS = "./generated/prove_verify.r1cs";
const GROTH16_PTAU_FILE = "../powersOfTau/powersOfTau28_hez_final_19.ptau";
const ZKEY_FILE = "./generated/circuit-prove_verify.zkey";
const VKEY_FILE = "./generated/vkey-prove_verify.json";
const ARTIFACTS_DIR = path.join(__dirname, "artifacts_bench_prove_verify");
const RAPIDSNARK_BIN = process.env.RAPIDSNARK_BIN || "prover";
const CIRCOM_BIN = process.env.CIRCOM_BIN || process.env.CIRCOM || "circom";

const N = parseInt(process.env.BENCH_N ?? "10", 10);
const BENCH_WARMUP = parseInt(process.env.BENCH_WARMUP ?? "1", 10);
const VERIFY_WARMUP = parseInt(process.env.BENCH_VERIFY_WARMUP ?? "0", 10);
const VERBOSE = process.argv.includes("--verbose");
const QUIET = !VERBOSE;
const KEEP_ARTIFACTS = process.argv.includes("--keep-artifacts") || process.env.KEEP_ARTIFACTS === "1";

const zk = zkCommon.createZkUtils(__dirname);
const { ensureDir, writeJson, resolvePath } = zk;

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
  try { fs.rmSync(path.join(__dirname, "generated"), { recursive: true, force: true }); } catch {}
}

function feToBigInt(F, x) {
  return BigInt(F.toString(x));
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

function signPoseidonScalar({ eddsa, babyJub, sk, msgField }) {
  const F = eddsa.F;
  const subOrder = BigInt(babyJub.subOrder);
  const r = randomScalarMod(subOrder, { nonZero: true });
  const A = babyJub.mulPointEscalar(babyJub.Base8, sk);
  const R8 = babyJub.mulPointEscalar(babyJub.Base8, r);
  const hm = eddsa.poseidon([R8[0], R8[1], A[0], A[1], msgField]);
  const hms = feToBigInt(F, hm);
  const S = mod(r + mod(hms * 8n * sk, subOrder), subOrder);
  return { R8, S };
}

function initCredentialOnce({ babyJub, F, eddsa, poseidon, prime }) {
  const baseNow = 1710000000000n;
  const maxBirthDate = baseNow - compute18YearsMs();

  const issuerPrv = crypto.randomBytes(32);
  const issuerPubPoint = eddsa.prv2pub(issuerPrv);
  const issuerPubKey = [eddsa.F.toString(issuerPubPoint[0]), eddsa.F.toString(issuerPubPoint[1])];

  const sk = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const elgamalPubKeyPoint = babyJub.mulPointEscalar(babyJub.Base8, sk);
  const elgamalPubKey = [F.toString(elgamalPubKeyPoint[0]), F.toString(elgamalPubKeyPoint[1])];

  const userSk = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const IDPoint = babyJub.mulPointEscalar(babyJub.Base8, userSk);
  const IDx = feToBigInt(F, IDPoint[0]);
  const IDy = feToBigInt(F, IDPoint[1]);

  const birthDate = maxBirthDate - ms(365);
  const validFrom = baseNow - ms(1);
  const validUntil = baseNow + ms(365);

  const labels = [
    "IDx", "IDy", "name", "familyName", "birthDate", "validFrom", "validUntil",
    "addressStreet", "addressNumber", "addressLocalityNumber", "addressCity",
    "addressCanton", "addressCountry", "cantonOfOrigin", "attr_14", "attr_15",
    "attr_16", "attr_17", "attr_18", "attr_19", "attr_20", "attr_21", "attr_22",
    "attr_23", "attr_24", "attr_25", "attr_26", "attr_27", "attr_28", "attr_29",
    "attr_30", "attr_31",
  ];
  const claimNames = labels.map((l) => computeClaimName({ poseidon, prime }, l));
  const claimValues = new Array(NUM_ATTRS).fill(0n);
  claimValues[0] = IDx;
  claimValues[1] = IDy;
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

  let acc = poseidon.F.e(0n);
  for (let i = 0; i < NUM_ATTRS; i++) {
    acc = poseidon([acc, claimNames[i], poseidon.F.e(claimValues[i])]);
  }
  const sig = eddsa.signPoseidon(issuerPrv, acc);

  return {
    babyJub,
    F,
    eddsa,
    poseidon,
    prime,
    issuerPrv,
    baseNow,
    maxBirthDate,
    userSk,
    elgamalPubKeyPoint,
    elgamalPubKey,
    issuerPubKey,
    claimNames,
    claimValues,
    birthDate,
    validFrom,
    validUntil,
    IDx,
    IDy,
    sig_R: [eddsa.F.toString(sig.R8[0]), eddsa.F.toString(sig.R8[1])],
    sig_S: sig.S,
    claimNamesStr: claimNames.map((x) => poseidon.F.toString(x)),
    claimValuesStr: claimValues.map((v) => v.toString()),
  };
}

function withRevocationIndex(cred, slot, index, label = "revocationIndex") {
  const claimNames = cred.claimNames.slice();
  const claimValues = cred.claimValues.slice();
  claimNames[slot] = computeClaimName({ poseidon: cred.poseidon, prime: cred.prime }, label);
  claimValues[slot] = BigInt(index);

  let acc = cred.poseidon.F.e(0n);
  for (let i = 0; i < NUM_ATTRS; i++) {
    acc = cred.poseidon([acc, claimNames[i], cred.poseidon.F.e(claimValues[i])]);
  }
  const sig = cred.eddsa.signPoseidon(cred.issuerPrv, acc);

  return {
    ...cred,
    claimNames,
    claimValues,
    claimNamesStr: claimNames.map((x) => cred.poseidon.F.toString(x)),
    claimValuesStr: claimValues.map((v) => v.toString()),
    sig_R: [cred.eddsa.F.toString(sig.R8[0]), cred.eddsa.F.toString(sig.R8[1])],
    sig_S: sig.S,
  };
}

function buildShowInput(cred, showIndex) {
  const { babyJub, F, eddsa, poseidon, baseNow, maxBirthDate, userSk, elgamalPubKeyPoint, elgamalPubKey } =
    cred;
  const now = baseNow + BigInt(showIndex);
  const t = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const randomVal1 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const randomVal2 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });

  const r2Q = babyJub.mulPointEscalar(elgamalPubKeyPoint, randomVal2);
  const tagMsg = poseidon([poseidon.F.e(t), r2Q[0], r2Q[1]]);
  const c4Sig = signPoseidonScalar({ eddsa, babyJub, sk: userSk, msgField: tagMsg });

  return {
    elgamalPubKey,
    issuerPubKey: cred.issuerPubKey,
    t: t.toString(),
    now: now.toString(),
    maxBirthDate: maxBirthDate.toString(),
    idxClaimName: cred.claimNamesStr[0],
    idyClaimName: cred.claimNamesStr[1],
    bdClaimName: cred.claimNamesStr[4],
    vfClaimName: cred.claimNamesStr[5],
    vuClaimName: cred.claimNamesStr[6],
    claimNames: cred.claimNamesStr,
    claimValues: cred.claimValuesStr,
    IDx: cred.IDx.toString(),
    IDy: cred.IDy.toString(),
    birthDate: cred.birthDate.toString(),
    validFrom: cred.validFrom.toString(),
    validUntil: cred.validUntil.toString(),
    sig_R: cred.sig_R,
    sig_S: cred.sig_S.toString(),
    c4Sig_R: [eddsa.F.toString(c4Sig.R8[0]), eddsa.F.toString(c4Sig.R8[1])],
    c4Sig_S: c4Sig.S.toString(),
    randomVal1: randomVal1.toString(),
    randomVal2: randomVal2.toString(),
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

function statsForSummary(arr) {
  if (!arr.length) return null;
  const s = stats(arr);
  return { minMs: s.min, maxMs: s.max, avgMs: s.avg, medianMs: s.median, p95Ms: s.p95 };
}

async function runBenchmark() {
  ensureDir(ARTIFACTS_DIR);
  ensureDir("./generated");

  if (!VERBOSE) {
    console.log("Setting up Groth16 artifacts (compile + zkey + witness generator on first run).");
    console.log("  This can take several minutes with no other output — use --verbose for details.\n");
  }

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

  const babyJub = await buildBabyjub();
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const crypto_ctx = { babyJub, F: babyJub.F, eddsa, poseidon, prime: poseidon.F.p };
  const credential = initCredentialOnce(crypto_ctx);

  const witnessMs = [];
  const proveMs = [];
  const verifyMs = [];
  let failures = 0;

  const snarkjs = require("snarkjs");
  const vkeyObj = JSON.parse(fs.readFileSync(path.join(__dirname, "generated", `vkey-${DEMO_NAME}.json`), "utf8"));

  const warmupIters = Math.max(0, BENCH_WARMUP);
  const totalIters = N + warmupIters;

  if (!VERBOSE) {
    console.log(`Iterations: ${N}` + (warmupIters ? ` (+${warmupIters} warmup discarded)` : ""));
    console.log(`Cleanup after run: ${KEEP_ARTIFACTS ? "disabled (--keep-artifacts)" : "enabled (default)"}\n`);
  }

  for (let i = 0; i < totalIters; i++) {
    const isWarmup = i < warmupIters;
    const iterDir = path.join(ARTIFACTS_DIR, `iter_${String(i).padStart(4, "0")}`);
    ensureDir(iterDir);

    const tW0 = zk.nowNs();
    const input = buildShowInput(credential, i);
    writeJson(path.join(iterDir, "input.json"), input);
    const wRes = zk.exec(`${cppWitnessBin} ${path.join(iterDir, "input.json")} ${path.join(iterDir, "witness.wtns")}`);
    const wMs = zk.nsToMs(zk.nowNs() - tW0);
    if (!wRes.ok) {
      console.error(`  iter ${i}: witness FAILED`);
      if (VERBOSE && (wRes.stderr || wRes.stdout)) console.error(wRes.stderr || wRes.stdout);
      failures++;
      continue;
    }

    const tP0 = zk.nowNs();
    const pRes = zk.exec(`${RAPIDSNARK_BIN} ${ZKEY_FILE} ${path.join(iterDir, "witness.wtns")} ${path.join(iterDir, "proof.json")} ${path.join(iterDir, "public.json")}`);
    const pMs = zk.nsToMs(zk.nowNs() - tP0);
    const proofAbs = resolvePath(path.join(iterDir, "proof.json"));
    const publicAbs = resolvePath(path.join(iterDir, "public.json"));
    if (!pRes.ok) {
      console.error(`  iter ${i}: prove FAILED`);
      if (VERBOSE && (pRes.stderr || pRes.stdout)) console.error(pRes.stderr || pRes.stdout);
      failures++;
      continue;
    }
    if (!fs.existsSync(proofAbs) || !fs.existsSync(publicAbs)) {
      console.error(`  iter ${i}: prove produced no proof/public outputs`);
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
      console.error(`  iter ${i}: verify FAILED`);
      failures++;
      continue;
    }

    if (!isWarmup) {
      witnessMs.push(wMs);
      proveMs.push(pMs);
      verifyMs.push(vMs);
    }

    if (!QUIET && !isWarmup) {
      const shownIter = `${String(i - warmupIters + 1).padStart(3)}/${N}`;
      process.stdout.write(
        `  [${shownIter}] witness=${wMs.toFixed(0)}ms  prove=${pMs.toFixed(0)}ms  verify=${vMs.toFixed(0)}ms  total=${(wMs + pMs + vMs).toFixed(0)}ms\n`
      );
    }
  }

  const successful = witnessMs.length;
  const summary = {
    meta: {
      type: "zk-friendly",
      variant: "prove_verify",
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
      proverTotal: statsForSummary(witnessMs.map((w, i) => w + proveMs[i])),
      fullCycle: statsForSummary(witnessMs.map((w, i) => w + proveMs[i] + verifyMs[i])),
    },
  };

  const outDir = resolvePath(ARTIFACTS_DIR);
  const ts = new Date().toISOString().replaceAll(":", "-");
  fs.writeFileSync(path.join(outDir, `summary_${ts}.json`), JSON.stringify(summary, null, 2));
  fs.writeFileSync(path.join(outDir, "summary_latest.json"), JSON.stringify(summary, null, 2));

  if (!VERBOSE) {
    console.log(
      `\nSummary written: ${path.join(outDir, "summary_latest.json")}` +
        (KEEP_ARTIFACTS ? " (artifacts kept)" : " (artifacts cleaned)")
    );
    if (successful > 0 && summary.statsMs.fullCycle) {
      console.log(`  full cycle avg: ${summary.statsMs.fullCycle.avgMs.toFixed(1)} ms (${successful}/${N} ok)`);
      if (summary.statsMs.verify) {
        console.log(
          `  verify median: ${summary.statsMs.verify.medianMs.toFixed(1)} ms` +
            ` (max ${summary.statsMs.verify.maxMs.toFixed(1)} ms — occasional GC spikes; use median for small BENCH_N)`
        );
      }
    } else if (failures > 0) {
      console.log(`  ${failures} iteration(s) failed`);
    }
  }

  if (!KEEP_ARTIFACTS) cleanupArtifactsKeepSummaries(outDir);
  if (!KEEP_ARTIFACTS) cleanupGeneratedOutputs();

  if (failures > 0) throw new Error(`${failures} iteration(s) failed`);
  return summary;
}

if (require.main === module) {
  runBenchmark()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}

module.exports = {
  initCredentialOnce,
  buildShowInput,
  withRevocationIndex,
  computeClaimName,
};
