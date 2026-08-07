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

function sha256Utf8ToField(message, modulus) {
  const digest = crypto.createHash("sha256").update(message, "utf8").digest();
  return bytesToBigIntBE(digest) % BigInt(modulus);
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
  sha256Utf8ToField,
  randomScalarMod,
};
