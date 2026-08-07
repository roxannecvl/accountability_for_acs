"use strict";

const { getPoseidon } = require("./poseidon_cjs");
const { G, pointSub } = require("./babyjub_noble");
const {
  randomScalarMod,
  modInv,
} = require("./crypto_common");
const { BABYJUB_ORDER } = require("./crypto_babyjub");
const { c4TagMessage, signC4, verifyC4, getEddsaContext } = require("./c4_binding");

const aff = (p) => {
  const { x, y } = p.toAffine();
  return [x, y];
};

const ptKey = (p) => {
  const [x, y] = aff(p);
  return `${x},${y}`;
};

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

/** One recurring ID in `recurringPct` of slots; rest unique. C4 = EdDSA on Poseidon(t, D2). */
function buildCftBatch(poseidon, pkAg, n, recurringPct, benchCtx) {
  const eddsaCtx = benchCtx?.eddsaCtx;
  if (!eddsaCtx) {
    throw new Error("buildCftBatch: requires eddsaCtx from initBenchContext()");
  }

  const pidThreshold = Math.max(2, Math.ceil(n * 0.1));
  const nRecurring = Math.max(Math.round(n * recurringPct), pidThreshold);
  const nUnique = n - nRecurring;
  const idRecurringSk = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
  const idRecurring = G.multiply(idRecurringSk);

  const idSlots = [];
  for (let i = 0; i < nRecurring; i++) {
    idSlots.push({ IDu: idRecurring, userSk: idRecurringSk });
  }
  for (let i = 0; i < nUnique; i++) {
    const userSk = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    idSlots.push({ IDu: G.multiply(userSk), userSk });
  }
  shuffle(idSlots);

  const mkCft = ({ IDu, userSk }) => {
    const r1 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    const r2 = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    const t = randomScalarMod(BABYJUB_ORDER, { nonZero: true });
    const C1 = G.multiply(r1);
    const C2 = G.multiply(r2);
    const C3 = IDu.add(pkAg.multiply(r1));
    const d2Aff = aff(pkAg.multiply(r2));
    const tagMsg = c4TagMessage(poseidon, t, d2Aff);
    const C4 = signC4({
      eddsa: eddsaCtx.eddsa,
      babyJub: eddsaCtx.babyJub,
      userSk,
      tagMsgField: tagMsg,
    });
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

async function initBenchContext() {
  const poseidon = await getPoseidon();
  const keys = setupKeys();
  const eddsaCtx = await getEddsaContext();
  return { poseidon, keys, eddsaCtx };
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

function verifyC4ForCft(poseidon, cft, IDu, d2) {
  return verifyC4({
    poseidon,
    IDuAff: aff(IDu),
    t: BigInt(cft.t),
    d2Aff: aff(d2),
    c4Sig: cft.C4,
  });
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
    if (!verifyC4ForCft(poseidon, cfts[i], IDu, d2)) {
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
    if (!verifyC4ForCft(poseidon, e, ID, d2)) {
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
  initBenchContext,
  setupKeys,
  buildCftBatch,
  benchManyCfts,
  benchLinkDecrypt,
  fitTimeModel,
  partialDecrypt,
};
