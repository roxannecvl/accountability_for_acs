"use strict";

const crypto = require("crypto");

function bytesToBigIntBE(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

function mod(a, m) {
  const x = BigInt(a) % BigInt(m);
  return x >= 0n ? x : x + BigInt(m);
}

/** Modular inverse of a mod m (m prime or a invertible). */
function modInv(a, m) {
  const M = BigInt(m);
  let t = 0n;
  let newT = 1n;
  let r = M;
  let newR = mod(a, M);
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1n) throw new Error("modInv: not invertible");
  if (t < 0n) t += M;
  return t;
}

function randomScalarMod(modulus, { nonZero = false } = {}) {
  const m = BigInt(modulus);
  while (true) {
    const buf = crypto.randomBytes(32);
    const x = bytesToBigIntBE(buf) % m;
    if (!nonZero || x !== 0n) return x;
  }
}

module.exports = {
  mod,
  modInv,
  randomScalarMod,
};
