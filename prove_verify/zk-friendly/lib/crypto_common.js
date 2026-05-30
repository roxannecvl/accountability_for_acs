"use strict";

const crypto = require("crypto");

const BN254_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

function bytesToBigIntBE(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

function bigIntToBytesBE(x, len) {
  let v = BigInt(x);
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bigIntToBufferBE(x, len) {
  return Buffer.from(bigIntToBytesBE(x, len));
}

function bytesToU64BE(bytes, offset) {
  let x = 0n;
  for (let i = 0; i < 8; i++) {
    x = (x << 8n) | BigInt(bytes[offset + i]);
  }
  return x;
}

function mod(a, m) {
  const x = BigInt(a) % BigInt(m);
  return x >= 0n ? x : x + BigInt(m);
}

function egcd(a, b) {
  let old_r = BigInt(a);
  let r = BigInt(b);
  let old_s = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return { g: old_r, x: old_s };
}

function modInv(a, m) {
  const mm = BigInt(m);
  const { g, x } = egcd(mod(a, mm), mm);
  if (g !== 1n) throw new Error("No modular inverse");
  return mod(x, mm);
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function sha256ToBigIntBE(buf) {
  return bytesToBigIntBE(sha256(buf));
}

function sha256Utf8ToBigIntBE(message) {
  const digest = crypto.createHash("sha256").update(message, "utf8").digest();
  return bytesToBigIntBE(digest);
}

function sha256Utf8ToField(message, modulus) {
  return sha256Utf8ToBigIntBE(message) % BigInt(modulus);
}

function randomScalarMod(modulus, { nonZero = false } = {}) {
  const m = BigInt(modulus);
  while (true) {
    const buf = crypto.randomBytes(32);
    const x = bytesToBigIntBE(buf) % m;
    if (!nonZero || x !== 0n) return x;
  }
}

function parseHex32Bytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error("Expected 32-byte hex (64 hex chars)");
  }
  return Buffer.from(clean, "hex");
}

function to0xHexFixed(x, bytes) {
  if (bytes != null) return `0x${bigIntToBufferBE(x, bytes).toString("hex")}`;
  return `0x${BigInt(x).toString(16)}`;
}

function u128ToBuf16BE(x) {
  return bigIntToBufferBE(x, 16);
}

module.exports = {
  BN254_PRIME,

  bytesToBigIntBE,
  bigIntToBytesBE,
  bigIntToBufferBE,
  bytesToU64BE,

  mod,
  modInv,

  sha256,
  sha256ToBigIntBE,
  sha256Utf8ToBigIntBE,
  sha256Utf8ToField,

  randomScalarMod,

  parseHex32Bytes,
  to0xHexFixed,
  u128ToBuf16BE,
};

