#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

// `@noble/curves@1.9.7` declares an `"exports"` field that does not expose
// `./package.json`, so plain `require("@noble/curves/package.json")` fails on
// Node >= 17 with ERR_PACKAGE_PATH_NOT_EXPORTED. Read the file directly.
const noblePkgPath = path.join(
  path.dirname(require.resolve("@noble/curves/abstract/curve")),
  "..",
  "package.json"
);
const pkg = JSON.parse(fs.readFileSync(noblePkgPath, "utf8"));

const { G } = require("./babyjub_noble");
const {
  getPoseidon,
  setupKeys,
  buildCftBatch,
  benchManyCfts,
  benchLinkDecrypt,
} = require("./cft_bench_lib");

const CIRCOM_BASE8_X =
  5299619240641551281634865583518297030282874472190772894086521144482721001553n;
const CIRCOM_BASE8_Y =
  16950150798460657717958625567821834550301663161624707787222815936182638968203n;

(async () => {
  const { x, y } = G.toAffine();
  const baseOk = x === CIRCOM_BASE8_X && y === CIRCOM_BASE8_Y;
  console.log("@noble/curves", pkg.version, "| Base8 match circom:", baseOk);
  if (!baseOk) {
    console.log("  noble BASE x", x.toString().slice(0, 24) + "...");
    console.log("  circom  x ", CIRCOM_BASE8_X.toString().slice(0, 24) + "...");
  }

  const poseidon = await getPoseidon();
  const keys = setupKeys();
  for (const pct of [0.1, 0.2, 0.5]) {
    const batch = buildCftBatch(poseidon, keys.pkAg, 100, pct);
    benchManyCfts(poseidon, batch, keys);
    benchLinkDecrypt(poseidon, batch, keys);
    console.log("ok n=100 recurring=", Math.round(pct * 100) + "%");
  }
  console.log("verify done");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
