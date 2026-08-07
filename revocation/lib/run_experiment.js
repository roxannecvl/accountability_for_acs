#!/usr/bin/env node
"use strict";

/**
 * Grid experiment for one benchmark: set_size × (recurring_pct for link only) × runs.
 * Usage: node run_experiment.js direct-decrypt
 *        node run_experiment.js link-decrypt
 */

const fs = require("fs");
const path = require("path");
const {
  initBenchContext,
  buildCftBatch,
  benchManyCfts,
  benchLinkDecrypt,
  fitTimeModel,
} = require("./cft_bench_lib");

const SIZES = [10, 20, 50, 100, 500, 1000, 2000, 4000, 8000];
/** direct-decrypt: recurring mix does not affect timing (one batch per size). */
const DIRECT_RECURRING_PCTS = [0.1];
/** link-decrypt: sweep recurring ID rate. */
const LINK_RECURRING_PCTS = [0.1, 0.5];
const RUNS = Number(process.env.EXPERIMENT_RUNS || 10);
const OUT_DIR = path.join(__dirname, "..", "results");
const VALID_BENCHMARKS = ["direct-decrypt", "link-decrypt"];

function resolveBenchmark() {
  const name = process.argv[2] || process.env.EXPERIMENT_BENCH;
  if (!name || !VALID_BENCHMARKS.includes(name)) {
    console.error("Usage: node run_experiment.js <direct-decrypt|link-decrypt>");
    console.error("  or:  EXPERIMENT_BENCH=direct-decrypt npm run experiment:direct-decrypt");
    process.exit(1);
  }
  return name;
}

function parseRecurringPctsEnv() {
  const raw = process.env.EXPERIMENT_RECURRING_PCTS;
  if (!raw) return null;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => Number(s) / 100);
}

function recurringPctsForBenchmark(benchmark) {
  const fromEnv = parseRecurringPctsEnv();
  if (fromEnv?.length) return fromEnv;
  return benchmark === "direct-decrypt" ? DIRECT_RECURRING_PCTS : LINK_RECURRING_PCTS;
}

function nsToMs(ns) {
  return Number(ns) / 1e6;
}

function csvEscape(v) {
  const s = String(v);
  return s.includes(",") || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
}

function writeCsv(filePath, headers, rows) {
  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((h) => csvEscape(row[h] ?? "")).join(","));
  }
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
}

function meanStd(values) {
  const n = values.length;
  if (n === 0) return { mean: 0, std: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const variance = values.reduce((a, v) => a + (v - mean) ** 2, 0) / n;
  return { mean, std: Math.sqrt(variance) };
}

async function runScenario(benchmark, benchCtx, setSize, recurringPct, run) {
  const batch = buildCftBatch(
    benchCtx.poseidon,
    benchCtx.keys.pkAg,
    setSize,
    recurringPct,
    benchCtx
  );
  const result =
    benchmark === "direct-decrypt"
      ? benchManyCfts(benchCtx.poseidon, batch, benchCtx.keys)
      : benchLinkDecrypt(benchCtx.poseidon, batch, benchCtx.keys);

  if (
    benchmark === "link-decrypt" &&
    result.n_after_filter !== batch.nRecurring
  ) {
    throw new Error(
      `${benchmark} n=${setSize} pct=${recurringPct} run=${run}: ` +
        `expected ${batch.nRecurring} after filter, got ${result.n_after_filter}`
    );
  }

  return {
    benchmark,
    set_size: setSize,
    recurring_pct: Math.round(recurringPct * 100),
    run,
    pid_threshold: batch.pidThreshold,
    n_recurring_expected: batch.nRecurring,
    n_after_filter: result.n_after_filter,
    t_total_ms: nsToMs(result.t_total_ns),
    t_link_ms: nsToMs(result.t_link_ns),
    t_decrypt_ms: nsToMs(result.t_decrypt_ns),
    t_per_input_cft_ms: nsToMs(result.t_total_ns) / setSize,
    t_ngo_ms: nsToMs(result.t_ngo_ns),
    t_judge_ms: nsToMs(result.t_judge_ns),
    t_police_ms: nsToMs(result.t_police_ns),
  };
}

async function runExperiment(benchmark, options = {}) {
  const sizes = options.sizes ?? (
    process.env.EXPERIMENT_SIZES
      ? process.env.EXPERIMENT_SIZES.split(",").map(Number)
      : SIZES
  );
  const recurringPcts = options.recurringPcts ?? recurringPctsForBenchmark(benchmark);
  const prefix = path.join(OUT_DIR, benchmark);

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const benchCtx = options.benchCtx ?? (await initBenchContext());

  const allRuns = [];
  const totalScenarios = sizes.length * recurringPcts.length * RUNS;
  let done = 0;

  console.log("CFT experiment: %s", benchmark);
  console.log(
    "  sizes=%s recurring%%=%s runs=%d",
    sizes.join(","),
    recurringPcts.map((p) => Math.round(p * 100)).join(","),
    RUNS
  );
  if (benchmark === "direct-decrypt") {
    console.log("  (direct-decrypt: recurring%% is not swept — one batch per set_size)");
  }
  console.log("  model: t_total_ms ≈ t1·set_size + t2·set_size_after_filter");
  if (benchmark === "link-decrypt") {
    console.log("  PID threshold = 10%% of set_size");
  }
  console.log("");

  for (const setSize of sizes) {
    for (const recurringPct of recurringPcts) {
      for (let run = 1; run <= RUNS; run++) {
        done += 1;
        process.stdout.write(
          `[${done}/${totalScenarios}] n=${setSize} recurring=${Math.round(recurringPct * 100)}% run=${run} ... `
        );
        const row = await runScenario(
          benchmark,
          benchCtx,
          setSize,
          recurringPct,
          run
        );
        allRuns.push(row);
        console.log(`${row.t_total_ms.toFixed(1)} ms`);
      }
    }
  }

  const runHeaders = [
    "benchmark",
    "set_size",
    "recurring_pct",
    "run",
    "pid_threshold",
    "n_recurring_expected",
    "n_after_filter",
    "t_total_ms",
    "t_link_ms",
    "t_decrypt_ms",
    "t_per_input_cft_ms",
    "t_ngo_ms",
    "t_judge_ms",
    "t_police_ms",
  ];

  writeCsv(`${prefix}_runs.csv`, runHeaders, allRuns);

  const summaryRows = [];
  for (const setSize of sizes) {
    for (const recurringPct of recurringPcts) {
      const pct = Math.round(recurringPct * 100);
      const subset = allRuns.filter(
        (r) => r.set_size === setSize && r.recurring_pct === pct
      );
      const tTotal = subset.map((r) => r.t_total_ms);
      const tLink = subset.map((r) => r.t_link_ms);
      const tDecrypt = subset.map((r) => r.t_decrypt_ms);
      const tPer = subset.map((r) => r.t_per_input_cft_ms);
      const nAfter = subset.map((r) => r.n_after_filter);
      const st = meanStd(tTotal);
      const su = meanStd(tLink);
      const sd = meanStd(tDecrypt);
      const sp = meanStd(tPer);
      summaryRows.push({
        benchmark,
        set_size: setSize,
        recurring_pct: pct,
        runs: RUNS,
        pid_threshold: subset[0]?.pid_threshold ?? "",
        n_after_filter_mean: meanStd(nAfter).mean,
        t_total_mean_ms: st.mean.toFixed(3),
        t_total_std_ms: st.std.toFixed(3),
        t_link_mean_ms: su.mean.toFixed(3),
        t_decrypt_mean_ms: sd.mean.toFixed(3),
        t_per_input_cft_mean_ms: sp.mean.toFixed(4),
      });
    }
  }

  writeCsv(
    `${prefix}_summary.csv`,
    [
      "benchmark",
      "set_size",
      "recurring_pct",
      "runs",
      "pid_threshold",
      "n_after_filter_mean",
      "t_total_mean_ms",
      "t_total_std_ms",
      "t_link_mean_ms",
      "t_decrypt_mean_ms",
      "t_per_input_cft_mean_ms",
    ],
    summaryRows
  );

  const samples = allRuns.map((r) => ({
    x: r.set_size,
    z: r.n_after_filter,
    y: r.t_total_ms,
  }));
  const { t1, t2, collapsed } = fitTimeModel(samples);
  const formula = collapsed
    ? `t_total_ms ≈ ${t1?.toFixed(4) ?? "?"}·set_size`
    : `t_total_ms ≈ ${t1?.toFixed(4) ?? "?"}·set_size + ${t2?.toFixed(4) ?? "?"}·set_size_after_filter`;

  writeCsv(
    `${prefix}_fit.csv`,
    ["benchmark", "t1_ms_per_input_cft", "t2_ms_per_after_filter_cft", "formula", "n_samples"],
    [
      {
        benchmark,
        t1_ms_per_input_cft: t1 == null ? "" : t1.toFixed(6),
        t2_ms_per_after_filter_cft: t2 == null ? "" : t2.toFixed(6),
        formula,
        n_samples: samples.length,
      },
    ]
  );

  console.log("\nWrote:");
  console.log(`  ${prefix}_runs.csv`);
  console.log(`  ${prefix}_summary.csv  (x=set_size, y=recurring_pct)`);
  console.log(`  ${prefix}_fit.csv`);
  console.log(`  ${formula}`);

  return { benchmark, prefix, formula, benchCtx };
}

async function main() {
  await runExperiment(resolveBenchmark());
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = {
  runExperiment,
  VALID_BENCHMARKS,
};
