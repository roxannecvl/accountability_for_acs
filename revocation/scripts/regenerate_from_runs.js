#!/usr/bin/env node
"use strict";

/** Regenerate *_summary.csv and *_fit.csv from an existing *_runs.csv. */

const fs = require("fs");
const path = require("path");
const { fitTimeModel } = require("../lib/cft_bench_lib");

const VALID = ["direct-decrypt", "link-decrypt", "mpc-decrypt"];

const RUNS_HEADERS = [
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

function parseCsv(text) {
  const lines = text.trim().split("\n");
  const headers = lines[0].split(",");
  return lines.slice(1).map((line) => {
    const vals = line.split(",");
    const row = {};
    headers.forEach((h, i) => {
      row[h] = vals[i];
    });
    for (const k of [
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
    ]) {
      const n = Number(row[k]);
      row[k] = Number.isFinite(n) ? n : row[k];
    }
    return row;
  });
}

function meanStd(values) {
  const n = values.length;
  if (n === 0) return { mean: 0, std: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const variance = values.reduce((a, v) => a + (v - mean) ** 2, 0) / n;
  return { mean, std: Math.sqrt(variance) };
}

function nPairs(n) {
  return (n * (n - 1)) / 2;
}

function fitPairwiseModel(rows) {
  const xs = rows.map((r) => nPairs(r.set_size));
  const ys = rows.map((r) => r.t_total_ms);
  const denom = xs.reduce((a, x) => a + x * x, 0);
  if (denom === 0) return { k: null, r2: 0 };
  const k = xs.reduce((a, x, i) => a + x * ys[i], 0) / denom;
  const ssRes = xs.reduce((a, x, i) => a + (ys[i] - k * x) ** 2, 0);
  const ssTot = ys.reduce((a, y) => a + y * y, 0);
  const r2 = ssTot === 0 ? 0 : 1 - ssRes / ssTot;
  return { k, r2 };
}

function writeCsv(filePath, headers, rows) {
  const esc = (v) => {
    const s = String(v ?? "");
    return s.includes(",") || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((h) => esc(row[h])).join(","));
  }
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
}

function regenerateDirectOrLink(benchmark, allRuns) {
  const prefix = path.join(__dirname, "..", "results", benchmark);
  const sizes = [...new Set(allRuns.map((r) => r.set_size))].sort((a, b) => a - b);
  const recurringPcts = [...new Set(allRuns.map((r) => r.recurring_pct))]
    .filter((p) => p !== "" && Number.isFinite(Number(p)))
    .map(Number)
    .sort((a, b) => a - b);

  const summaryRows = [];
  for (const setSize of sizes) {
    for (const pct of recurringPcts) {
      const subset = allRuns.filter(
        (r) => r.set_size === setSize && r.recurring_pct === pct
      );
      if (subset.length === 0) continue;
      const st = meanStd(subset.map((r) => r.t_total_ms));
      const su = meanStd(subset.map((r) => r.t_link_ms));
      const sd = meanStd(subset.map((r) => r.t_decrypt_ms));
      const sp = meanStd(subset.map((r) => r.t_per_input_cft_ms));
      summaryRows.push({
        benchmark,
        set_size: setSize,
        recurring_pct: pct,
        runs: subset.length,
        pid_threshold: subset[0].pid_threshold,
        n_after_filter_mean: meanStd(subset.map((r) => r.n_after_filter)).mean,
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

  return { sizes, summaryRows: summaryRows.length, formula, n_samples: samples.length, prefix };
}

function regenerateMpc(allRuns) {
  const benchmark = "mpc-decrypt";
  const prefix = path.join(__dirname, "..", "results", benchmark);
  const sorted = [...allRuns].sort(
    (a, b) => a.set_size - b.set_size || a.run - b.run
  );

  writeCsv(`${prefix}_runs.csv`, RUNS_HEADERS, sorted.map((r) => ({
    ...r,
    benchmark,
    recurring_pct: "",
    pid_threshold: "",
    n_recurring_expected: "",
    n_after_filter: r.set_size,
    t_link_ms: 0,
    t_decrypt_ms: r.t_total_ms,
    t_per_input_cft_ms: Number((r.t_total_ms / r.set_size).toFixed(7)),
    t_ngo_ms: "",
    t_judge_ms: "",
    t_police_ms: "",
  })));

  const sizes = [...new Set(sorted.map((r) => r.set_size))].sort((a, b) => a - b);
  const summaryRows = sizes.map((setSize) => {
    const subset = sorted.filter((r) => r.set_size === setSize);
    const st = meanStd(subset.map((r) => r.t_total_ms));
    const sp = meanStd(subset.map((r) => r.t_per_input_cft_ms));
    return {
      benchmark,
      set_size: setSize,
      runs: subset.length,
      n_after_filter_mean: setSize,
      t_total_mean_ms: st.mean.toFixed(3),
      t_total_std_ms: st.std.toFixed(3),
      t_link_mean_ms: "0.000",
      t_decrypt_mean_ms: st.mean.toFixed(3),
      t_per_input_cft_mean_ms: sp.mean.toFixed(4),
    };
  });

  writeCsv(
    `${prefix}_summary.csv`,
    [
      "benchmark",
      "set_size",
      "runs",
      "n_after_filter_mean",
      "t_total_mean_ms",
      "t_total_std_ms",
      "t_link_mean_ms",
      "t_decrypt_mean_ms",
      "t_per_input_cft_mean_ms",
    ],
    summaryRows
  );

  const { k, r2 } = fitPairwiseModel(sorted);
  const formula = `t_total_ms ≈ ${k?.toFixed(4) ?? "?"}·set_size·(set_size - 1)/2`;

  writeCsv(
    `${prefix}_fit.csv`,
    ["benchmark", "k_ms_per_pair", "formula", "r2", "n_samples"],
    [
      {
        benchmark,
        k_ms_per_pair: k == null ? "" : k.toFixed(6),
        formula,
        r2: r2.toFixed(6),
        n_samples: sorted.length,
      },
    ]
  );

  return {
    sizes,
    summaryRows: summaryRows.length,
    formula,
    n_samples: sorted.length,
    prefix,
  };
}

function main() {
  const benchmark = process.argv[2];
  if (!benchmark || !VALID.includes(benchmark)) {
    console.error(`Usage: node regenerate_from_runs.js <${VALID.join("|")}>`);
    process.exit(1);
  }

  const prefix = path.join(__dirname, "..", "results", benchmark);
  const allRuns = parseCsv(fs.readFileSync(`${prefix}_runs.csv`, "utf8"));

  const result =
    benchmark === "mpc-decrypt"
      ? regenerateMpc(allRuns)
      : regenerateDirectOrLink(benchmark, allRuns);

  console.log(`sizes: ${result.sizes.join(",")}`);
  console.log(`summary rows: ${result.summaryRows}`);
  console.log(result.formula);
  console.log(`n_samples: ${result.n_samples}`);
  if (benchmark === "mpc-decrypt") {
    console.log(`Wrote ${result.prefix}_runs.csv (sorted)`);
  }
  console.log(`Wrote ${result.prefix}_summary.csv`);
  console.log(`Wrote ${result.prefix}_fit.csv`);
}

module.exports = {
  fitPairwiseModel,
  nPairs,
  parseCsv,
  writeCsv,
  RUNS_HEADERS,
};

if (require.main === module) {
  main();
}
