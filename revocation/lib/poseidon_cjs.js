"use strict";

/**
 * Load circomlibjs buildPoseidon for Node 18+ CJS.
 * Use require("circomlibjs") — its "exports.require" points at build/main.cjs.
 */
function loadBuildPoseidon() {
  let mod;
  try {
    mod = require("circomlibjs");
  } catch (e) {
    throw new Error(
      `circomlibjs not installed. In workspace/revocation: npm install\n${e.message}`
    );
  }

  const fn = mod.buildPoseidon;
  if (typeof fn === "function") return fn;

  if (mod.default && typeof mod.default.buildPoseidon === "function") {
    return mod.default.buildPoseidon;
  }

  try {
    const entry = require.resolve("circomlibjs");
    mod = require(entry);
  } catch (e) {
    throw new Error(`circomlibjs resolve failed: ${e.message}`);
  }

  if (typeof mod.buildPoseidon !== "function") {
    const keys = Object.keys(mod).slice(0, 16).join(", ");
    throw new Error(
      `buildPoseidon missing (typeof=${typeof mod.buildPoseidon}, exports: ${keys || "none"}). ` +
        "Need circomlibjs@0.1.7 — rm -rf node_modules && npm install"
    );
  }
  return mod.buildPoseidon;
}

const buildPoseidon = loadBuildPoseidon();

let poseidonPromise;

async function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

module.exports = { buildPoseidon, getPoseidon, loadBuildPoseidon };
