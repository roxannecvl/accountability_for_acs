"use strict";

const { getPoseidon } = require("./poseidon_cjs");
const { G, pointSub } = require("./babyjub_noble");
const {
  randomScalarMod,
  modInv,
} = require("../benchmark/zk-friendly/lib/crypto_common");
const { BABYJUB_ORDER } = require("../benchmark/zk-friendly/lib/crypto_babyjub");

const aff = (p) => {
  const { x, y } = p.toAffine();
  return [x, y];
};

const ptKey = (p) => {
  const [x, y] = aff(p);
  return `${x},${y}`;
};

function c4Hash(poseidon, IDu, t, P) {
  return poseidon.F.toString(poseidon([IDu[0], IDu[1], t, P[0], P[1]]));
}

function setupKeys() {
  const key = () => {
    const sk = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    return { sk, pk: G.multiply(sk) };
  };
  const police = key();
  const judge = key();
  const ngo = key();
  return { police, judge, ngo, pkAg: police.pk.add(judge.pk).add(ngo.pk) };
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** One recurring ID in `recurringPct` of slots; rest unique. */
function buildCftBatch(poseidon, pkAg, n, recurringPct) {
  const pidThreshold = Math.max(2, Math.ceil(n * 0.1));
  const nRecurring = Math.max(Math.round(n * recurringPct), pidThreshold);
  const nUnique = n - nRecurring;
  const idRecurring = G.multiply(randomScalarMod(BABYJUB_ORDER, { nonZero: true }));

  const idSlots = [];
  for (let i = 0; i < nRecurring; i++) idSlots.push(idRecurring);
  for (let i = 0; i < nUnique; i++) {
    idSlots.push(G.multiply(randomScalarMod(BABYJUB_ORDER, { nonZero: true })));
  }
  shuffle(idSlots);

  const mkCft = (IDu) => {
    const r1 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    const r2 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    const t = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    const C1 = G.multiply(r1);
    const C2 = G.multiply(r2);
    const C3 = IDu.add(pkAg.multiply(r1));
    const C4 = c4Hash(poseidon, aff(IDu), t, aff(pkAg.multiply(r2)));
    return { C1, C2, C3, C4, t: t.toString(), D1: C1, D3: C3 };
  };

  const cfts = idSlots.map(mkCft);
  return {
    cfts,
    nRecurring,
    nUnique,
    recurringPct,
    idKeyRecurring: ptKey(idRecurring),
    pidThreshold,
  };
}

function partialDecrypt(C1, C2, sk) {
  return { d1: C1.multiply(sk), d2: C2.multiply(sk) };
}

function batchLink(entries, sk) {
  const k = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const out = entries.map((e) => {
    const D1p = e.D1;
    const D3p = e.D3;
    return {
      ...e,
      D1: D1p.multiply(k),
      D3: pointSub(D3p, D1p.multiply(sk)).multiply(k),
    };
  });
  return { entries: out, k };
}

function filterRecurringPids(entries, minCount) {
  const counts = new Map();
  for (const e of entries) {
    const k = ptKey(e.D3);
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const recurring = new Set();
  for (const [k, c] of counts) {
    if (c >= minCount) recurring.add(k);
  }
  return entries.filter((e) => recurring.has(ptKey(e.D3)));
}

function reverseK(point, k) {
  return point.multiply(modInv(k, BABYJUB_ORDER));
}

/** Direct decrypt (many_CFTs). All n CFTs; n_after = n. */
function benchManyCfts(poseidon, batch, keys) {
  const { cfts } = batch;
  const n = cfts.length;

  let t0 = process.hrtime.bigint();
  const ngoShares = cfts.map((c) => partialDecrypt(c.C1, c.C2, keys.ngo.sk));
  const tNgo = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  const judgeShares = cfts.map((c) => partialDecrypt(c.C1, c.C2, keys.judge.sk));
  const tJudge = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  for (let i = 0; i < cfts.length; i++) {
    const police = partialDecrypt(cfts[i].C1, cfts[i].C2, keys.police.sk);
    const d1 = police.d1.add(ngoShares[i].d1).add(judgeShares[i].d1);
    const d2 = police.d2.add(ngoShares[i].d2).add(judgeShares[i].d2);
    const IDu = pointSub(cfts[i].C3, d1);
    if (c4Hash(poseidon, aff(IDu), BigInt(cfts[i].t), aff(d2)) !== cfts[i].C4) {
      throw new Error("C4 verification failed (many_CFTs)");
    }
  }
  const tPolice = Number(process.hrtime.bigint() - t0);

  const tTotal = tNgo + tJudge + tPolice;
  return {
    n,
    n_after_filter: n,
    t_ngo_ns: tNgo,
    t_judge_ns: tJudge,
    t_police_ns: tPolice,
    t_link_ns: 0,
    t_decrypt_ns: tTotal,
    t_total_ns: tTotal,
  };
}

/** Link then decrypt. Link on all n; decrypt on filtered recurring only. */
function benchLinkDecrypt(poseidon, batch, keys) {
  const n = batch.cfts.length;
  const minCount = batch.pidThreshold;
  let entries = batch.cfts.map((e) => ({ ...e, D1: e.C1, D3: e.C3 }));

  let t0 = process.hrtime.bigint();
  const pu = batchLink(entries, keys.police.sk);
  entries = pu.entries;
  let tPoliceLink = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  const ju = batchLink(entries, keys.judge.sk);
  entries = ju.entries;
  const tJudgeLink = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  const nu = batchLink(entries, keys.ngo.sk);
  entries = nu.entries;
  const tNgoLink = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  const filtered = filterRecurringPids(entries, minCount);
  const tFilter = Number(process.hrtime.bigint() - t0);

  const nAfter = filtered.length;
  const tLink = tPoliceLink + tJudgeLink + tNgoLink + tFilter;

  t0 = process.hrtime.bigint();
  const ngoOut = filtered.map((e) => ({
    ...e,
    pidN: reverseK(e.D3, nu.k),
    d2N: e.C2.multiply(keys.ngo.sk),
  }));
  const tNgoDec = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  const judgeOut = ngoOut.map((e) => ({
    ...e,
    pidJ: reverseK(e.pidN, ju.k),
    d2J: e.C2.multiply(keys.judge.sk),
  }));
  const tJudgeDec = Number(process.hrtime.bigint() - t0);

  t0 = process.hrtime.bigint();
  for (const e of judgeOut) {
    const ID = reverseK(e.pidJ, pu.k);
    const d2 = e.C2.multiply(keys.police.sk).add(e.d2N).add(e.d2J);
    if (c4Hash(poseidon, aff(ID), BigInt(e.t), aff(d2)) !== e.C4) {
      throw new Error("C4 verification failed (link-decrypt)");
    }
  }
  const tPoliceDec = Number(process.hrtime.bigint() - t0);

  const tDecrypt = tNgoDec + tJudgeDec + tPoliceDec;
  const tTotal = tLink + tDecrypt;

  return {
    n,
    n_after_filter: nAfter,
    pid_threshold: minCount,
    t_ngo_ns: tNgoLink + tNgoDec,
    t_judge_ns: tJudgeLink + tJudgeDec,
    t_police_ns: tPoliceLink + tPoliceDec,
    t_link_ns: tLink,
    t_decrypt_ns: tDecrypt,
    t_total_ns: tTotal,
  };
}

/** OLS: y ≈ t1·x + t2·z  (if x≡z, collapses to y ≈ t1·x) */
function fitTimeModel(samples) {
  const collapsed = samples.every((s) => s.x === s.z);
  if (collapsed) {
    let sxx = 0;
    let sxy = 0;
    for (const { x, y } of samples) {
      sxx += x * x;
      sxy += x * y;
    }
    const t1 = sxx === 0 ? null : sxy / sxx;
    return { t1, t2: 0, collapsed: true };
  }

  let sxx = 0;
  let sxz = 0;
  let szz = 0;
  let sxy = 0;
  let szy = 0;
  for (const { x, z, y } of samples) {
    sxx += x * x;
    sxz += x * z;
    szz += z * z;
    sxy += x * y;
    szy += z * y;
  }
  const det = sxx * szz - sxz * sxz;
  if (det === 0) return { t1: null, t2: null, collapsed: false };
  return {
    t1: (sxy * szz - szy * sxz) / det,
    t2: (sxx * szy - sxz * sxy) / det,
    collapsed: false,
  };
}

module.exports = {
  getPoseidon,
  setupKeys,
  buildCftBatch,
  benchManyCfts,
  benchLinkDecrypt,
  fitTimeModel,
};
