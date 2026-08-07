"use strict";

const { G } = require("./babyjub_noble");
const { mod, randomScalarMod } = require("./crypto_common");
const { BABYJUB_ORDER } = require("./crypto_babyjub");

/** Tag message for C4: Poseidon(t, D2x, D2y) — matches zk-friendly prove_verify.circom. */
function c4TagMessage(poseidon, t, d2Aff) {
  const F = poseidon.F;
  const tFe = F.e(typeof t === "bigint" ? t : BigInt(t));
  return poseidon([tFe, F.e(BigInt(d2Aff[0])), F.e(BigInt(d2Aff[1]))]);
}

function signC4({ eddsa, babyJub, userSk, tagMsgField }) {
  const F = eddsa.F;
  const subOrder = BigInt(babyJub.subOrder);
  const r = randomScalarMod(subOrder, { nonZero: true });
  const A = babyJub.mulPointEscalar(babyJub.Base8, userSk);
  const R8 = babyJub.mulPointEscalar(babyJub.Base8, r);
  const hm = eddsa.poseidon([R8[0], R8[1], A[0], A[1], tagMsgField]);
  const hms = BigInt(F.toObject(hm));
  const S = mod(r + mod(hms * 8n * BigInt(userSk), subOrder), subOrder);
  return {
    R8: [F.toString(R8[0]), F.toString(R8[1])],
    S: S.toString(),
  };
}

function normalizeC4Sig(c4Sig) {
  if (typeof c4Sig === "string") return c4Sig;
  return {
    R8: [String(c4Sig.R8[0]), String(c4Sig.R8[1])],
    S: String(c4Sig.S),
  };
}

/** Verify C4 = EdDSA_{IDu}(Poseidon(t, D2)). Uses @noble/curves (not circomlibjs verifyPoseidon). */
function verifyC4({ poseidon, IDuAff, t, d2Aff, c4Sig }) {
  const sig = normalizeC4Sig(c4Sig);
  const S = BigInt(sig.S);
  if (S >= BABYJUB_ORDER) return false;

  const F = poseidon.F;
  const msg = c4TagMessage(poseidon, t, d2Aff);
  const Ax = F.e(BigInt(IDuAff[0]));
  const Ay = F.e(BigInt(IDuAff[1]));
  const R8x = F.e(BigInt(sig.R8[0]));
  const R8y = F.e(BigInt(sig.R8[1]));

  const hm = poseidon([R8x, R8y, Ax, Ay, msg]);
  const hms = BigInt(F.toObject(hm));
  const hmScaled = mod(hms * 8n, BABYJUB_ORDER);

  const { babyjubjub } = require("./babyjub_noble");
  const pub = babyjubjub.Point.fromAffine({ x: BigInt(IDuAff[0]), y: BigInt(IDuAff[1]) });
  const r8 = babyjubjub.Point.fromAffine({ x: BigInt(sig.R8[0]), y: BigInt(sig.R8[1]) });

  const pLeft = G.multiply(S);
  const pRight = r8.add(pub.multiply(hmScaled));
  const l = pLeft.toAffine();
  const r = pRight.toAffine();
  return l.x === r.x && l.y === r.y;
}

let eddsaContextPromise = null;

async function getEddsaContext() {
  if (!eddsaContextPromise) {
    eddsaContextPromise = (async () => {
      const { buildBabyjub, buildEddsa } = require("circomlibjs");
      const babyJub = await buildBabyjub();
      const eddsa = await buildEddsa();
      return { babyJub, eddsa };
    })();
  }
  return eddsaContextPromise;
}

module.exports = {
  c4TagMessage,
  signC4,
  verifyC4,
  normalizeC4Sig,
  getEddsaContext,
};
