"use strict";

const { randomScalarMod } = require("./crypto_common");

const BABYJUB_ORDER = BigInt(
  "2736030358979909402780800718157159386076813972158567259200215660948447373041"
);

function randomScalarBabyJub({ nonZero = false } = {}) {
  return randomScalarMod(BABYJUB_ORDER, { nonZero });
}

function babyjubPointFromStrings(F, xy) {
  return [F.e(BigInt(xy[0])), F.e(BigInt(xy[1]))];
}

function babyjubPointToStrings(F, p) {
  return [F.toString(p[0]), F.toString(p[1])];
}

function babyjubPointNeg(babyJub, p) {
  return [babyJub.F.neg(p[0]), p[1]];
}

function babyjubPointSub(babyJub, P, Q) {
  return babyJub.addPoint(P, babyjubPointNeg(babyJub, Q));
}

function babyjubElgamalEncrypt({ babyJub, F, msgPoint, randomVal, elgamalSPubKeyPoint }) {
  const c1Point = babyJub.mulPointEscalar(babyJub.Base8, randomVal);
  const rsQPoint = babyJub.mulPointEscalar(elgamalSPubKeyPoint, randomVal);
  const c2Point = babyJub.addPoint(msgPoint, rsQPoint);

  return {
    c1Point,
    c2Point,
    rsQPoint,
    c1: [F.toString(c1Point[0]), F.toString(c1Point[1])],
    c2: [F.toString(c2Point[0]), F.toString(c2Point[1])],
  };
}

function babyjubPoseidonCommitment({ poseidon, F, msgPoint, rsQPoint, s }) {
  const mx = BigInt(F.toString(msgPoint[0]));
  const my = BigInt(F.toString(msgPoint[1]));
  const rsqx = BigInt(F.toString(rsQPoint[0]));
  const rsqy = BigInt(F.toString(rsQPoint[1]));
  const ss = BigInt(s);

  const comFe = poseidon([mx, my, rsqx, rsqy, ss]);
  return poseidon.F.toString(comFe);
}

module.exports = {
  BABYJUB_ORDER,
  randomScalarBabyJub,

  babyjubPointFromStrings,
  babyjubPointToStrings,
  babyjubPointNeg,
  babyjubPointSub,

  babyjubElgamalEncrypt,
  babyjubPoseidonCommitment,
};

