#!/usr/bin/env node
"use strict";

console.log("node", process.version, process.arch);
console.log("cwd", process.cwd());

try {
  require.resolve("@noble/curves/misc");
  console.log("@noble/curves ok (misc)");
} catch (e) {
  console.log("@noble/curves MISSING — npm install @noble/curves@1.9.7");
}

try {
  const entry = require.resolve("circomlibjs");
  console.log("circomlibjs entry", entry);
  console.log("buildPoseidon", typeof require("circomlibjs").buildPoseidon);
} catch (e) {
  console.log("circomlibjs error:", e.message);
}

try {
  require("big-integer");
  console.log("big-integer ok");
} catch (e) {
  console.log("big-integer MISSING");
}

const { loadBuildPoseidon } = require("./poseidon_cjs");
console.log("poseidon_cjs", typeof loadBuildPoseidon());

const { G, BASE8_X, BASE8_Y } = require("./babyjub_noble");
const { x, y } = G.toAffine();
console.log("Base8 match circom:", x === BASE8_X && y === BASE8_Y);
