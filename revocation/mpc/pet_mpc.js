#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

/**
 * CFTCondOpen-style benchmark: unlink then decrypt (CFT → PID → ID).
 * - Sequential BatchUnlink: Police → Judge → NGO
 * - NGO counts PIDs (D3 after NGO unlink), keeps recurring only (count ≥ τ)
 * - Reverse k_N, k_J, k_P and BatchDeanonymize (D2 = sk · C2)
 * - Police verifies C4 = Poseidon(ID, t, D2)
 *
 * No signatures. Same ID mix as many_CFTs: 20% A, 5% B, 75% unique.
 */

const { getPoseidon } = require("../lib/poseidon_cjs");
const { G, pointSub } = require("../lib/babyjub_noble");
const {
  randomScalarMod,
  modInv,
} = require("../lib/crypto_common");
const { BABYJUB_ORDER } = require("../lib/crypto_babyjub");
const aff = (p) => {
    const { x, y } = p.toAffine();
    return [x, y];
};
const ptKey = (p) => {
    const [x, y] = aff(p);
    return `${x},${y}`;
};

function c4Hash(poseidon, IDu, t, d2Aff) {
    return poseidon.F.toString(poseidon([IDu[0], IDu[1], t, d2Aff[0], d2Aff[1]]));
}

function setupKeys() {
    const mainSk = randomScalarMod(BABYJUB_ORDER, { nonZero: true });

    const numShares = 3;
    const Q = BABYJUB_ORDER;
    // Handle negatives: BigInt % Q can be negative in JS.
    const mod = (x) => ((x % Q) + Q) % Q;

    const shares = [];
    let acc = 0n;
    for (let i = 0; i < numShares - 1; i++) {
        const s = randomScalarMod(Q, { nonZero: true });
        shares.push(s);
        acc = mod(acc + s);
    }
    // Final share is fixed so that the sum equals mainSk mod q.
    const finalShare = mod(BigInt(mainSk) - acc);
    shares.push(finalShare);

    const police = shares[0];
    const judge = shares[1];
    const ngo = shares[2];

    return{
        police,
        judge,
        ngo,
        pkAg: G.multiply(mainSk)
    }
}

function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function buildCftBatch(poseidon, pkAg, n) {
    const nA = Math.round(n * 0.2);
    const nB = Math.round(n * 0.05);
    const nUnique = n - nA - nB;
    const idA = G.multiply(randomScalarMod(BABYJUB_ORDER, { nonZero: true }));
    const idB = G.multiply(randomScalarMod(BABYJUB_ORDER, { nonZero: true }));

    const idSlots = [];
    for (let i = 0; i < nA; i++) idSlots.push(idA);
    for (let i = 0; i < nB; i++) idSlots.push(idB);
    for (let i = 0; i < nUnique; i++) {
        idSlots.push(G.multiply(randomScalarMod(BABYJUB_ORDER, { nonZero: true })));
    }
    shuffle(idSlots);

    const entries = idSlots.map((IDu) => {
        const r1 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
        const r2 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
        const t = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
        const C1 = G.multiply(r1);
        const C2 = G.multiply(r2);
        const C3 = IDu.add(pkAg.multiply(r1));
        const C4 = c4Hash(poseidon, aff(IDu), t, aff(pkAg.multiply(r2)));
        return { C1, C2, C3, C4, t: t.toString(), D1: C1, D3: C3, IDu };
    });

    return { entries, nA, nB, nUnique, idKeyA: ptKey(idA), idKeyB: ptKey(idB) };
}

function generateBlinding() {
    return randomScalarMod(BABYJUB_ORDER, { nonZero: true });
}

function partialDecrypt(C, sk) {
    return { d: C.multiply(sk)};
}

// Threshold-decrypt a CFT's (C1, C3) to recover ID.
function thresholdDecryptId(entry, keys) {
  const d1 = entry.C1.multiply(keys.police)
              .add(entry.C1.multiply(keys.judge))
              .add(entry.C1.multiply(keys.ngo));
  return entry.C3.subtract(d1);
}

// Threshold-compute sk·C2 (= r2·pkAg) for the Poseidon binding check.
function thresholdScalarMulC2(entry, keys) {
  return entry.C2.multiply(keys.police)
          .add(entry.C2.multiply(keys.judge))
          .add(entry.C2.multiply(keys.ngo));
}

// Returns { ok, ID, d2 }: ok iff Poseidon(ID, t, sk·C2) == C4.
function checkIntegrity(entry, keys, poseidon) {
  const ID = thresholdDecryptId(entry, keys);
  const d2 = thresholdScalarMulC2(entry, keys);
  const expectedC4 = c4Hash(poseidon, aff(ID), BigInt(entry.t), aff(d2));
  return { ok: expectedC4 === entry.C4, ID, d2 };
}

function writeMpcInputsDistributed({ spdzPath, MprimeMat, N }) {
  const dir = path.join(spdzPath, "Player-Data");
  fs.mkdirSync(dir, { recursive: true });

  const p0 = [];
  for (let i = 0; i < N; i++) {
    for (let j = i + 1; j < N; j++) {
      const { x, y } = MprimeMat[i][j].toAffine();
      p0.push(x.toString(), y.toString());
    }
  }
  fs.writeFileSync(path.join(dir, "Input-P0-0"), p0.join("\n") + "\n");
  // Other players have empty input files.
  fs.writeFileSync(path.join(dir, "Input-P1-0"), "");
  fs.writeFileSync(path.join(dir, "Input-P2-0"), "");

  const nPairs = (N * (N - 1)) / 2;
  console.log(`wrote inputs for ${N} CFTs / ${nPairs} pairs:`);
  console.log(`  Input-P0-0: ${p0.length} lines (2 per pair: M'.x, M'.y)`);
}

// One scenario run: build a corpus, run the PET phase, run MPC, do the
// integrity check, append a row to the CSV. Returns the row for caller
// inspection if needed.
async function runOnce({ iter, numCfts, tau, poseidon, spdzPath, mpcSrcPath, csvPath }) {
    const { compileMpc, runMpc, parsePredicates, parseSpdzStats, appendCsv } =
      require("./mpc_runner");

    const keys = setupKeys();
    const batch = buildCftBatch(poseidon, keys.pkAg, numCfts);
    const nRec = batch.nA + batch.nB;

    const tPetStart = process.hrtime.bigint();

    const zeroArray = [];
    for (let i = 0; i < numCfts; i++) {
        zeroArray.push(G.ZERO);
    }

    const BlindedC1Diffs = [];
    const BlindedC3Diffs = [];

    for (let i = 0; i < numCfts; i++) {
        BlindedC1Diffs.push([...zeroArray]);
        BlindedC3Diffs.push([...zeroArray]);
    }

    for (let i = 0; i < numCfts; i++) {
        for (let j = i; j < numCfts; j++) {
            const b = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
            const BlindedC1Diff = batch.entries[i].C1.subtract(batch.entries[j].C1).multiply(b);
            const BlindedC3Diff = batch.entries[i].C3.subtract(batch.entries[j].C3).multiply(b);
            
            BlindedC1Diffs[i][j] = BlindedC1Diff;
            BlindedC1Diffs[j][i] = BlindedC1Diff; // Symmetric difference
            BlindedC3Diffs[i][j] = BlindedC3Diff;
            BlindedC3Diffs[j][i] = BlindedC3Diff;
        }
    }

    // Partial decryption by police
    const partialDecryptionsPoliceC1 = [];
    for (let i = 0; i < numCfts; i++) {
        partialDecryptionsPoliceC1.push([]);
        for (let j = 0; j < i; j++) {
            const pdC1 = partialDecryptionsPoliceC1[j][i]
            partialDecryptionsPoliceC1[i].push(pdC1);
        }
        for (let j = i; j < numCfts; j++) {
            const pd = partialDecrypt(BlindedC1Diffs[i][j], keys.police);
            partialDecryptionsPoliceC1[i].push(pd.d);
        }
    }
    const petPhaseMs = Number(process.hrtime.bigint() - tPetStart) / 1e6;

    // Partial decryption by judge
    const partialDecryptionsJudgeC1 = [];
    for (let i = 0; i < numCfts; i++) {
        partialDecryptionsJudgeC1.push([]);
        for (let j = 0; j < i; j++) {
            const pdC1 = partialDecryptionsJudgeC1[j][i]
            partialDecryptionsJudgeC1[i].push(pdC1);
        }
        for (let j = i; j < numCfts; j++) {
            const pd = partialDecrypt(BlindedC1Diffs[i][j], keys.judge);
            partialDecryptionsJudgeC1[i].push(pd.d);
        }
    }

    // Partial decryption by NGO
    const partialDecryptionsNgoC1 = [];
    for (let i = 0; i < numCfts; i++) {
        partialDecryptionsNgoC1.push([]);
        for (let j = 0; j < i; j++) {
            const pdC1 = partialDecryptionsNgoC1[j][i]
            partialDecryptionsNgoC1[i].push(pdC1);
        }
        for (let j = i; j < numCfts; j++) {
            const pd = partialDecrypt(BlindedC1Diffs[i][j], keys.ngo);
            partialDecryptionsNgoC1[i].push(pd.d);
        }
    }

    // Now we emulate for MPC
    // Decrypt using the partial decryptions from police, judge, and NGO
    // Store the 2D array of decrypted differences for C1 and C3
    // in a file
    const fullDecryptedC1Diffs = [];
    const fullDecryptedC3Diffs = [];
    for (let i = 0; i < numCfts; i++) {
        fullDecryptedC1Diffs.push([]);
        fullDecryptedC3Diffs.push([]);
        for (let j = 0; j < numCfts; j++) {
            const fullDecryptionC1 = partialDecryptionsPoliceC1[i][j].add(partialDecryptionsJudgeC1[i][j]).add(partialDecryptionsNgoC1[i][j]);
            fullDecryptedC1Diffs[i].push(fullDecryptionC1);
            const fullDecryptionC3 = BlindedC3Diffs[i][j].subtract(fullDecryptionC1);
            fullDecryptedC3Diffs[i].push(fullDecryptionC3);
        }
    }

    writeMpcInputsDistributed({
        spdzPath,
        MprimeMat: fullDecryptedC3Diffs,   // M' computed in JS
        N: numCfts,
    });

    const fullName = await compileMpc({
      spdzPath, mpcSrcPath, name: "predicate_matrix_partials",
      args: [numCfts, tau],
    });

    // ── Timing: MPC wall + parse stderr for online/offline ─────────
    const tMpcStart = process.hrtime.bigint();
    const { stdouts, stderrs } = await runMpc({ spdzPath, fullName, T: 3 });
    const mpcWallMs = Number(process.hrtime.bigint() - tMpcStart) / 1e6;

    const predicates = parsePredicates(stdouts[0], numCfts);
    const flagged   = predicates.filter(Boolean).length;
    console.log(`# CFTs flagged: ${flagged}`);

    // Stats from party 0's combined stdout+stderr (MP-SPDZ writes timing
    // to stderr when run with -v).
    const stats = parseSpdzStats(stdouts[0] + "\n" + stderrs[0]);

    // ── Integrity check + conditional reveal ───────────────────────
    const tIntStart = process.hrtime.bigint();
    let nIntegrityChecked = 0, nIntegrityFailed = 0;
    const revealedIds = [];
    for (let i = 0; i < numCfts; i++) {
      if (!predicates[i]) continue;
      const { ok, ID } = checkIntegrity(batch.entries[i], keys, poseidon);
      nIntegrityChecked++;
      if (!ok) {
        nIntegrityFailed++;
        continue;
      }
      revealedIds.push(ptKey(ID));
    }
    const integrityMs = Number(process.hrtime.bigint() - tIntStart) / 1e6;
    const uniqueIds = new Set(revealedIds);

    console.log(`Integrity check: ${integrityMs.toFixed(2)} ms (${nIntegrityChecked} checked, ${nIntegrityFailed} failed)`);
    console.log(`Revealed unique IDs: ${uniqueIds.size}`);

    // ── CSV row ────────────────────────────────────────────────────
    const row = {
      ts: new Date().toISOString(),
      iter,
      n_cfts: numCfts,
      tau,
      n_recurring_expected: nRec,
      n_pairs: (numCfts * (numCfts - 1)) / 2,

      pet_phase_ms: petPhaseMs,

      mpc_wall_ms: mpcWallMs,
      mpc_total_ms:   stats.spdz_total_ms,
      mpc_online_ms:  stats.spdz_online_ms,
      mpc_offline_ms: stats.spdz_offline_ms,
      mpc_online_bytes:  stats.spdz_online_bytes,
      mpc_online_rounds: stats.spdz_online_rounds,
      mpc_offline_bytes: stats.spdz_offline_bytes,
      mpc_offline_rounds: stats.spdz_offline_rounds,
      mpc_data_sent_bytes:        stats.spdz_data_sent_bytes,
      mpc_global_data_sent_bytes: stats.spdz_global_data_sent_bytes,

      integrity_phase_ms:  integrityMs,
      n_flagged_by_mpc:    flagged,
      n_integrity_checked: nIntegrityChecked,
      n_integrity_failed:  nIntegrityFailed,
      n_unique_ids_revealed: uniqueIds.size,
    };
    appendCsv(csvPath, row);
    console.log(`appended row to ${csvPath}`);
    return row;
}

async function main() {
    // Sizes: accept either CFT_BENCH_NUMS (plural — comma/space-separated list)
    // or CFT_BENCH_NUM (singular). Plural wins if both are set.
    const numsRaw = process.env.CFT_BENCH_NUMS
        || process.env.CFT_BENCH_NUM
        || "10";
    const numsList = numsRaw
        .split(/[,\s]+/)
        .filter(Boolean)
        .map((s) => Number(s))
        .filter((n) => Number.isFinite(n) && n > 0);
    if (numsList.length === 0) {
        console.error("ERROR: CFT_BENCH_NUMS / CFT_BENCH_NUM produced an empty list.");
        process.exit(2);
    }

    const iterations = Number(process.env.CFT_BENCH_ITERS || 1);
    const minPidCount = Number(process.env.CFT_MIN_PID_COUNT || 2);
    const poseidon = await getPoseidon();

    const spdzPath = process.env.MP_SPDZ_PATH || "/home/smishy/mp-spdz-0.4.2";
    const mpcSrcPath = path.join(__dirname, "predicate_matrix_partials.mpc");
    const csvPath = process.env.RESULTS_CSV || path.join(__dirname, "results.csv");
    const tau = minPidCount;

    const totalRuns = iterations * numsList.length;
    console.log(
        `Running ${iterations} iter(s) × ${numsList.length} size(s) ` +
        `= ${totalRuns} scenario(s) at tau=${tau}`
    );
    console.log(`Sizes (N): [${numsList.join(", ")}]`);

    // Interleaved order:
    //   iter 1 → N₁, N₂, …, N_k
    //   iter 2 → N₁, N₂, …, N_k
    //   ...
    // (instead of: N₁ × all iters, then N₂ × all iters, ...)
    let done = 0;
    for (let iter = 1; iter <= iterations; iter++) {
        for (const numCfts of numsList) {
            done += 1;
            console.log(
                `\n──── [${done}/${totalRuns}] iter ${iter}/${iterations}  N=${numCfts} ────`
            );
            await runOnce({
                iter,
                numCfts,
                tau,
                poseidon,
                spdzPath,
                mpcSrcPath,
                csvPath,
            });
        }
    }
    console.log(
        `\n──── done. ${totalRuns} scenario(s) appended to ${csvPath} ────`
    );
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
