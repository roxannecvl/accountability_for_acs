#!/usr/bin/env node
"use strict";

/**
 * Longfellow: ProveVerify + CFT + packed status-list revocation (SHA-256 Merkle).
 *
 * Default: BENCH_N=10, REVOC_LOG2_LIST=12,16,20,24
 *
 * Env:
 *   BENCH_WARMUP=1   one discarded Google Benchmark repetition before the timed run
 *                    (same as prove-verify / prove-verify-no-cft; set 0 to skip)
 */

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  formatBenchmarkMinTimeForGbench,
  parseBenchmarkMinTimeSeconds,
} = require("../scripts/bench_gbench_common");

const STANDARD_ROOT = path.join(__dirname, "..");
const LONGFELLOW_ROOT = fs.existsSync(path.join(STANDARD_ROOT, "longfellow-zk", "lib", "CMakeLists.txt"))
  ? path.join(STANDARD_ROOT, "longfellow-zk")
  : STANDARD_ROOT;

const DEFAULT_LOG2 = [12, 16, 20, 24];

function parseLog2List() {
  const raw = process.env.REVOC_LOG2_LIST ?? process.env.REVOC_LOG2;
  if (!raw) return DEFAULT_LOG2;
  return String(raw)
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n));
}

function defaultBinPath() {
  return path.join(
    LONGFELLOW_ROOT,
    "clang-build-release",
    "circuits",
    "tests",
    "ec",
    "prove_verify_revocation_test"
  );
}

function stats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const n = sorted.length;
  if (!n) return null;
  const avg = arr.reduce((s, x) => s + x, 0) / n;
  return { min: sorted[0], max: sorted[n - 1], avg };
}

/** Packed SHA-256 status-list Merkle depth for population 2^revocLog2, B=253 bits/leaf. */
function packedMerkleDepth(revocLog2, bitsPerLeaf = 253) {
  const population = 1 << revocLog2;
  const numLeaves = Math.ceil(population / bitsPerLeaf);
  let padded = 1;
  while (padded < numLeaves) padded <<= 1;
  return Math.log2(padded);
}

function parseBenchmarkRows(rows) {
  const byName = new Map();
  for (const b of rows) {
    if (b.aggregate_name) continue;
    const name = String(b.name || b.run_name || "");
    if (!name) continue;
    const proveNs = Number(b.prove_ns);
    const verifyNs = Number(b.verify_ns);
    const entry = byName.get(name) || { prove: [], verify: [] };
    if (Number.isFinite(proveNs)) entry.prove.push(proveNs / 1e6);
    if (Number.isFinite(verifyNs)) entry.verify.push(verifyNs / 1e6);
    byName.set(name, entry);
  }
  return byName;
}

function extractLog2FromBenchName(name) {
  const m = String(name).match(/\/(\d+)$/);
  return m ? parseInt(m[1], 10) : null;
}

function benchWarmupEnabled() {
  const v = (process.env.BENCH_WARMUP ?? "1").trim().toLowerCase();
  return v !== "0" && v !== "false" && v !== "no";
}

/** Same flags as the measured run but `--benchmark_repetitions` forced to `n`. */
function benchArgsWithRepetitions(benchArgs, n) {
  let found = false;
  const out = benchArgs.map((a) => {
    if (a.startsWith("--benchmark_repetitions=")) {
      found = true;
      return `--benchmark_repetitions=${n}`;
    }
    return a;
  });
  if (!found) out.push(`--benchmark_repetitions=${n}`);
  return out;
}

function runGoogleBenchWarmup(bin, benchBase) {
  if (!benchWarmupEnabled()) return;
  const warmOut = path.join(os.tmpdir(), `longfellow-revoc-warm-${process.pid}-${Date.now()}.json`);
  const warmSeed = [
    ...benchBase,
    "--benchmark_format=console",
    `--benchmark_out=${warmOut}`,
    "--benchmark_out_format=json",
  ];
  const wargs = benchArgsWithRepetitions(warmSeed, 1);
  console.log(
    "[warmup] 1× Google Benchmark repetition (same filter/min_time). Live console; JSON discarded.\n"
  );
  spawnSync(bin, wargs, { stdio: "inherit" });
  try {
    fs.unlinkSync(warmOut);
  } catch {
    /* ignore */
  }
  console.log("[warmup] Done.\n");
}

function main() {
  const bin = process.env.LONGFELLOW_REVOC_BENCH_BIN || defaultBinPath();
  if (!fs.existsSync(bin)) {
    console.error(`Binary not found: ${bin}`);
    console.error(
      "Build: cmake -S lib -B clang-build-release && cmake --build clang-build-release --target prove_verify_revocation_test -j8"
    );
    process.exit(1);
  }

  const log2List = parseLog2List();
  const repetitions = parseInt(process.env.BENCH_N ?? process.env.BENCH_REPETITIONS ?? "10", 10);
  const min_time = process.env.BENCH_MIN_TIME || "0.05s";
  const filter =
    process.env.BENCH_FILTER ||
    `BM_ProveVerifyRevocationCombined_Packed_P256/(${log2List.join("|")})`;
  const artifactsDir = path.resolve(
    process.env.ARTIFACTS_DIR
      ? path.isAbsolute(process.env.ARTIFACTS_DIR)
        ? process.env.ARTIFACTS_DIR
        : path.join(STANDARD_ROOT, process.env.ARTIFACTS_DIR)
      : path.join(__dirname, "artifacts_bench_prove_verify_revocation")
  );
  fs.mkdirSync(artifactsDir, { recursive: true });

  parseBenchmarkMinTimeSeconds(min_time);

  console.log("Longfellow ProveVerify+CFT+packed revocation (SHA-256 Merkle)");
  console.log(`  scales: ${log2List.map((x) => `2^${x}`).join(", ")}`);
  console.log(`  filter = ${filter}`);
  console.log(`  repetitions = ${repetitions}`);
  console.log(
    `  warm-up: ${
      benchWarmupEnabled()
        ? "1× Google Benchmark repetition discarded before measured run (BENCH_WARMUP=0 to skip)"
        : "disabled (BENCH_WARMUP)"
    }\n`
  );

  const benchBase = [
    `--benchmark_filter=${filter}`,
    `--benchmark_repetitions=${repetitions}`,
    `--benchmark_report_aggregates_only=false`,
    `--benchmark_display_aggregates_only=false`,
    `--benchmark_min_time=${formatBenchmarkMinTimeForGbench(min_time, bin)}`,
    `--benchmark_iterations=1`,
  ];

  runGoogleBenchWarmup(bin, benchBase);

  const gbenchJsonPath = path.join(os.tmpdir(), `longfellow-revoc-${process.pid}.json`);
  const r = spawnSync(
    bin,
    [
      ...benchBase,
      "--benchmark_format=console",
      `--benchmark_out=${gbenchJsonPath}`,
      "--benchmark_out_format=json",
    ],
    { stdio: "inherit" }
  );

  let txt;
  try {
    txt = fs.readFileSync(gbenchJsonPath, "utf8");
  } catch (e) {
    console.error("Failed to read benchmark JSON:", e.message);
    process.exit(r.status ?? 1);
  } finally {
    try {
      fs.unlinkSync(gbenchJsonPath);
    } catch {}
  }

  const start = txt.indexOf("{");
  const end = txt.lastIndexOf("}");
  const json = JSON.parse(txt.slice(start, end + 1));
  const rows = json.benchmarks || [];
  const byName = parseBenchmarkRows(rows);

  const BITS_PER_LEAF = 253;
  const byScale = [];
  console.log("\n── Summary (avg ms) ──");
  for (const [name, v] of [...byName.entries()].sort()) {
    const proverTotal = stats(v.prove); // prove_ns = full prover (no witness/prove split)
    const verify = stats(v.verify);
    const revocLog2 = extractLog2FromBenchName(name);
    const row = {
      revocLog2,
      population: revocLog2 != null ? 1 << revocLog2 : null,
      merkleDepth: revocLog2 != null ? packedMerkleDepth(revocLog2, BITS_PER_LEAF) : null,
      verify,
      proverTotal,
    };
    byScale.push(row);
    console.log(
      `  2^${revocLog2} (depth ${row.merkleDepth})  prover=${proverTotal?.avg.toFixed(1) ?? "?"}  verify=${verify?.avg.toFixed(1) ?? "?"}`
    );
  }

  const summary = {
    meta: {
      type: "longfellow",
      revocLog2List: log2List,
      bitsPerLeaf: BITS_PER_LEAF,
      benchN: repetitions,
      warmup: benchWarmupEnabled() ? 1 : 0,
      timestampIso: new Date().toISOString(),
    },
    byScale,
  };

  const ts = new Date().toISOString().replaceAll(":", "-");
  fs.writeFileSync(path.join(artifactsDir, `summary_${ts}.json`), JSON.stringify(summary, null, 2));
  fs.writeFileSync(path.join(artifactsDir, "summary_latest.json"), JSON.stringify(summary, null, 2));
  console.log(`\nSummary: ${path.join(artifactsDir, "summary_latest.json")}`);
  process.exit(byScale.length ? 0 : r.status ?? 1);
}

main();
