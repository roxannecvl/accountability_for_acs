"use strict";

/** @noble/curves babyjub (CJS). Use `misc`, not `misc.js` (v1.x / Node 18). */
const { babyjubjub } = require("@noble/curves/misc");

/** circomlibjs BabyJub Base8 (= 8 · Generator), see circomlibjs/src/babyjub.js */
const BASE8_X =
  5299619240641551281634865583518297030282874472190772894086521144482721001553n;
const BASE8_Y =
  16950150798460657717958625567821834550301663161624707787222815936182638968203n;

function matchesBase8(point) {
  const { x, y } = point.toAffine();
  return x === BASE8_X && y === BASE8_Y;
}

/**
 * circom / iden3 use subgroup base B (Base8). noble 2.x sets Point.BASE = B;
 * noble 1.x sets Point.BASE = G (full-group generator) → use 8·BASE.
 */
function base8Generator() {
  const base = babyjubjub.Point.BASE;
  if (matchesBase8(base)) return base;
  const b8 = base.multiply(8n);
  if (matchesBase8(b8)) return b8;
  const { x, y } = b8.toAffine();
  throw new Error(
    "noble babyjub Point.BASE is not circom Base8 (expected B = 8·G). " +
      `got x=${x.toString().slice(0, 20)}… y=${y.toString().slice(0, 20)}…`
  );
}

const G = base8Generator();

function pointSub(p, q) {
  if (typeof p.subtract === "function") return p.subtract(q);
  return p.add(q.negate());
}

module.exports = { babyjubjub, G, pointSub, BASE8_X, BASE8_Y };
