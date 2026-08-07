#!/usr/bin/env node
"use strict";

/**
 * Run direct-decrypt then link-decrypt; writes six CSVs under results/.
 * Usage: npm run experiment
 *        EXPERIMENT_SIZES=100,500 EXPERIMENT_RUNS=2 npm run experiment
 */

const path = require("path");
const { initBenchContext } = require("./cft_bench_lib");
const { runExperiment } = require("./run_experiment");

const BENCHMARKS = ["direct-decrypt", "link-decrypt"];

async function main() {
  const benchCtx = await initBenchContext();

  for (let i = 0; i < BENCHMARKS.length; i++) {
    if (i > 0) console.log("\n" + "─".repeat(60) + "\n");
    await runExperiment(BENCHMARKS[i], { benchCtx });
  }

  console.log("\nAll experiments done. CSVs in results/:");
  for (const b of BENCHMARKS) {
    const prefix = path.join("results", b);
    console.log(`  ${prefix}_runs.csv`);
    console.log(`  ${prefix}_summary.csv`);
    console.log(`  ${prefix}_fit.csv`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
