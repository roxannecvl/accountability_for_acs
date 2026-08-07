#!/usr/bin/env node
"use strict";

/**
 * Longfellow (Google Benchmark): flat SHA vs Merkle attribute commitment.
 * Env / flags mirror the thesis script
 * `prove-verify/zk-friendly/merkle-vs-flat/bench_merkle_vs_flat.js`
 * (Circom workflow there → Google Benchmark JSON here).
 *
 * Environment (thesis names):
 *   TOTAL_ATTRS            comma-separated total attribute counts n (default 8,16,32,64)
 *   USED_ATTRS             comma-separated disclosure counts k (default 1,2,4,8,16)
 *   BENCH_N                outer repetitions → --benchmark_repetitions (default 10). Alias: BENCH_REPETITIONS.
 *   BENCH_ITERATIONS       inner iterations per repetition → --benchmark_iterations (default 1). Use 0 or auto for GB adaptive loop (min_time).
 *   BENCH_MIN_TIME         e.g. 0.05s
 *   BENCH_METRIC           real_time | cpu_time
 *   ARTIFACTS_DIR          subdir under stack root or absolute path for summary JSON
 *   LONGFELLOW_ATTR_BENCH_BIN   path to attr_commitment_experiment_test
 *   KEEP_ARTIFACTS=1       with --keep-artifacts
 *   CLEAN=1                with --clean: delete artifact dir before run
 *   BENCH_WARMUP           if 0/false/no, skip one discarded Google Benchmark run before the timed run (default: on, like zk-friendly +1 warmup).
 *
 * Flags:
 *   --verbose               after the run: per-benchmark sample stats (GB prints live console during warm-up and measured passes; JSON is read from a temp file on the measured pass only)
 *   --quiet  --compact  --keep-artifacts  --clean
 *   --bin PATH  --total-attrs / --attr LIST  --used-attrs / --used-attr LIST
 *   --n N  --repetitions N  --min_time T  --metric M  --iterations N  --out-dir DIR
 *   -h, --help
 */
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  formatBenchmarkMinTimeForGbench,
  parseBenchmarkMinTimeSeconds,
} = require("../scripts/bench_gbench_common");

/** Stack root (`prove-verify/standard` locally, `/bench` in Docker). */
const STANDARD_ROOT = path.join(__dirname, "..");
/** Longfellow C++ tree: `longfellow-zk/` when present; otherwise same as STANDARD_ROOT (flat `/bench` layout in Docker). */
const LONGFELLOW_ROOT = fs.existsSync(path.join(STANDARD_ROOT, "longfellow-zk", "lib", "CMakeLists.txt"))
  ? path.join(STANDARD_ROOT, "longfellow-zk")
  : STANDARD_ROOT;

const DEFAULT_TOTALS = [8, 16, 32, 64];
const DEFAULT_USED = [1, 2, 4, 8, 16];

function resolveArtifactsDir(defaultSubdir) {
  const raw = process.env.ARTIFACTS_DIR;
  if (!raw) return path.join(__dirname, defaultSubdir);
  return path.isAbsolute(raw) ? raw : path.join(STANDARD_ROOT, raw);
}

function benchWarmupEnabled() {
  const v = (process.env.BENCH_WARMUP ?? "1").trim().toLowerCase();
  return v !== "0" && v !== "false" && v !== "no";
}

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

function runGoogleBenchWarmup(bin, benchBase, opts = {}) {
  if (!benchWarmupEnabled()) return;
  const { compact } = opts;
  const warmOut = path.join(os.tmpdir(), `longfellow-warm-${process.pid}-${Date.now()}.json`);
  const warmSeed = [
    ...benchBase,
    "--benchmark_format=console",
    `--benchmark_out=${warmOut}`,
    "--benchmark_out_format=json",
  ];
  const wargs = benchArgsWithRepetitions(warmSeed, 1);
  if (!compact) {
    console.log(
      "[warmup] 1× Google Benchmark repetition (same filter/min_time). Live console; JSON is written to a temp file and discarded.\n"
    );
  }
  spawnSync(bin, wargs, { stdio: "inherit" });
  try {
    fs.unlinkSync(warmOut);
  } catch {
    /* ignore */
  }
  if (!compact) console.log("[warmup] Done.\n");
}

function printUsage(prog) {
  console.log(`Usage: node ${path.basename(prog)} [options]

Environment (thesis-style):
  TOTAL_ATTRS          Comma list of n (totals). Default: ${DEFAULT_TOTALS.join(",")}
  USED_ATTRS           Comma list of k (used / revealed counts). Default: ${DEFAULT_USED.join(",")}
  BENCH_N              Outer repetitions (statistical samples). Default 10. Alias: BENCH_REPETITIONS.
  BENCH_ITERATIONS     Inner iterations per repetition (default 1). auto or 0 = let Google Benchmark pick from min_time.
  BENCH_MIN_TIME       e.g. 0.05s
  BENCH_METRIC         real_time | cpu_time
  ARTIFACTS_DIR        Subdir under stack root or absolute path for summaries
  LONGFELLOW_ATTR_BENCH_BIN
  KEEP_ARTIFACTS=1     With --keep-artifacts
  CLEAN=1              With --clean: remove artifact dir before run
  BENCH_WARMUP=0      Skip the extra 1× repetition warm-up run before measurement

Flags:
  --verbose  After run: printStats (warm-up + measured: live GB console; JSON from temp file parsed after measured pass)
  --quiet  --compact  --keep-artifacts  --clean
  --bin PATH  --total-attrs LIST  --attr LIST  --used-attrs LIST  --used-attr LIST
  --n N  --repetitions N  --min_time T  --metric M  --iterations N  --out-dir DIR
  -h, --help
`);
}

function parseIntListEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return [...fallback];
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => Number(s));
  const ok = parts.filter((x) => Number.isInteger(x) && x > 0);
  return ok.length ? ok : [...fallback];
}

/** Google Benchmark --benchmark_iterations; default 1. null = omit flag (adaptive). */
function parseBenchInnerIterationsFromEnv() {
  const raw = (process.env.BENCH_ITERATIONS ?? "").trim().toLowerCase();
  if (raw === "auto" || raw === "0") return null;
  if (raw === "") return 1;
  const n = Number(process.env.BENCH_ITERATIONS);
  if (!Number.isInteger(n) || n < 1) return 1;
  return n;
}

function parseIterationsCli(v) {
  const t = String(v).trim().toLowerCase();
  if (t === "auto" || t === "0") return null;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error("--iterations must be a positive integer, or 0/auto for adaptive inner loop");
  }
  return n;
}

function parseIntListArg(s, fallback) {
  if (s == null || s === "") return [...fallback];
  const parts = String(s)
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((x) => Number(x));
  const ok = parts.filter((x) => Number.isInteger(x) && x > 0);
  return ok.length ? ok : [...fallback];
}

function isoForFilename(d = new Date()) {
  return d.toISOString().replaceAll(":", "-");
}

function stats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const n = sorted.length;
  if (!n) return null;
  const avg = arr.reduce((s, x) => s + x, 0) / n;
  const median = n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[Math.floor(n / 2)];
  const p95 = sorted[Math.floor((n - 1) * 0.95)];
  return { min: sorted[0], max: sorted[n - 1], avg, median, p95 };
}

function fmt(ms) {
  return ms.toFixed(2).padStart(9);
}

function printStats(label, arrMs) {
  if (!arrMs || !arrMs.length) return;
  const s = stats(arrMs);
  if (!s) return;
  console.log(
    `${label.padEnd(18)} min=${fmt(s.min)}ms  avg=${fmt(s.avg)}ms  median=${fmt(s.median)}ms  p95=${fmt(s.p95)}ms  max=${fmt(s.max)}ms`
  );
}

function defaultBinPath() {
  return path.join(
    LONGFELLOW_ROOT,
    "clang-build-release",
    "circuits",
    "tests",
    "ec",
    "attr_commitment_experiment_test"
  );
}

function parseArgs(argv) {
  const repEnv = process.env.BENCH_N ?? process.env.BENCH_REPETITIONS ?? "10";
  const out = {
    bin: process.env.LONGFELLOW_ATTR_BENCH_BIN || null,
    repetitions: Number(repEnv, 10) || 10,
    min_time: process.env.BENCH_MIN_TIME || "0.05s",
    metric: process.env.BENCH_METRIC === "cpu_time" ? "cpu_time" : "real_time",
    totals: parseIntListEnv("TOTAL_ATTRS", DEFAULT_TOTALS),
    used: parseIntListEnv("USED_ATTRS", DEFAULT_USED),
    iterations: parseBenchInnerIterationsFromEnv(),
    verbose: argv.includes("--verbose"),
    compact: argv.includes("--compact"),
    keepArtifacts: argv.includes("--keep-artifacts") || process.env.KEEP_ARTIFACTS === "1",
    clean: argv.includes("--clean") || process.env.CLEAN === "1",
    outDir: resolveArtifactsDir("artifacts_bench_merkle_vs_flat"),
  };

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const v = argv[i + 1];
    if (a === "--bin") out.bin = v, i++;
    else if (a === "--repetitions" || a === "--n") out.repetitions = Number(v), i++;
    else if (a === "--min_time") out.min_time = String(v), i++;
    else if (a === "--metric") out.metric = v, i++;
    else if (a === "--total-attrs" || a === "--attr") out.totals = parseIntListArg(v, out.totals), i++;
    else if (a === "--used-attrs" || a === "--used-attr") out.used = parseIntListArg(v, out.used), i++;
    else if (a === "--iterations") out.iterations = parseIterationsCli(v), i++;
    else if (a === "--out-dir") out.outDir = path.resolve(v), i++;
    else if (a === "--verbose") out.verbose = true;
    else if (a === "--compact") out.compact = true;
    else if (a === "--keep-artifacts") out.keepArtifacts = true;
    else if (a === "--clean") out.clean = true;
    else if (a === "--quiet") {
      /* thesis: quiet default; flag is a no-op */
    } else if (a === "--help" || a === "-h") {
      printUsage(argv[1] || "bench_merkle_vs_flat.js");
      process.exit(0);
    } else {
      throw new Error(`Unknown arg: ${a}`);
    }
  }

  if (!out.bin) {
    const d = defaultBinPath();
    if (fs.existsSync(d)) out.bin = d;
  }
  if (!out.bin) {
    const d = defaultBinPath();
    throw new Error(
      `Benchmark binary not found at ${d}. Build first (from longfellow-zk: cmake -S lib -B clang-build-release && cmake --build clang-build-release -j), or set LONGFELLOW_ATTR_BENCH_BIN / pass --bin PATH`
    );
  }
  if (!["real_time", "cpu_time"].includes(out.metric)) {
    throw new Error("--metric must be real_time or cpu_time");
  }
  if (!Number.isFinite(out.repetitions) || out.repetitions < 1) {
    throw new Error("--n / --repetitions / BENCH_N must be >= 1");
  }
  parseBenchmarkMinTimeSeconds(out.min_time);
  return out;
}

function mean(xs) {
  if (!xs.length) return null;
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

function toMs(x, unit) {
  if (unit === "ns") return x / 1e6;
  if (unit === "us") return x / 1e3;
  if (unit === "ms") return x;
  if (unit === "s") return x * 1e3;
  return null;
}

function baseName(runName) {
  return String(runName || "")
    .replace(/\/repetition:\d+$/, "")
    .replace(/_repetition_\d+$/, "");
}

function parseBenchName(name) {
  let m = /^BM_AttrSigCombined_(Flat|Merkle)\/(\d+)\/(\d+)$/.exec(name);
  if (m) {
    return { kind: "combined", mode: m[1].toLowerCase(), n: Number(m[2]), k: Number(m[3]) };
  }
  m = /^BM_AttrSig(Prover|Verifier)_(Flat|Merkle)\/(\d+)\/(\d+)$/.exec(name);
  if (!m) return null;
  return { kind: m[1].toLowerCase(), mode: m[2].toLowerCase(), n: Number(m[3]), k: Number(m[4]) };
}

/** Collect prove_ns / verify_ns from Combined rows; key `${mode}/${n}/${k}`. */
function collectCombinedSamples(rows, wantedN, wantedK) {
  const byKey = new Map();
  for (const b of rows) {
    if (b.aggregate_name) continue;
    const name = baseName(b.name || b.run_name || "");
    const meta = parseBenchName(name);
    if (!meta || meta.kind !== "combined") continue;
    if (!wantedN.has(meta.n) || !wantedK.has(meta.k)) continue;
    const proveNs = Number(b.prove_ns);
    const verifyNs = Number(b.verify_ns);
    if (!Number.isFinite(proveNs) || !Number.isFinite(verifyNs)) continue;
    const key = `${meta.mode}/${meta.n}/${meta.k}`;
    const cur = byKey.get(key) || { mode: meta.mode, n: meta.n, k: meta.k, proveMs: [], verifyMs: [] };
    cur.proveMs.push(proveNs / 1e6);
    cur.verifyMs.push(verifyNs / 1e6);
    byKey.set(key, cur);
  }
  return byKey;
}

function cellStr({ avgProverMs, avgVerifyMs }) {
  const p = avgProverMs == null ? "" : `${avgProverMs.toFixed(0)}`;
  const v = avgVerifyMs == null ? "" : `${avgVerifyMs.toFixed(0)}`;
  return p && v ? `${p}/${v}` : "";
}

function printRecapGrid(title, proverMap, verifyMap, totals, useds, metricLabel) {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`  ${title}`);
  console.log(`  cell = avgProverMs/avgVerifyMs (${metricLabel}; Google Benchmark repetitions)`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const colW = 12;
  const header = ["total\\used".padEnd(colW), ...useds.map((u) => String(u).padStart(colW))].join("");
  console.log(header);
  console.log("-".repeat(header.length));

  for (const t of totals) {
    const row = [String(t).padEnd(colW)];
    for (const u of useds) {
      const key = `${t}/${u}`;
      const cell = {
        avgProverMs: proverMap.get(key),
        avgVerifyMs: verifyMap.get(key),
      };
      row.push((cellStr(cell) || "").padStart(colW));
    }
    console.log(row.join(""));
  }
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function main() {
  const args = parseArgs(process.argv);
  const VERBOSE = args.verbose;

  if (args.clean) {
    try {
      fs.rmSync(args.outDir, { recursive: true, force: true });
    } catch {}
  }

  const wantedN = new Set(args.totals);
  const wantedK = new Set(args.used);
  const ns = [...wantedN].sort((a, b) => a - b);
  const ks = [...wantedK].sort((a, b) => a - b);

  const nRegex = [...ns].sort((a, b) => String(b).length - String(a).length || b - a).join("|");
  const kRegex = [...ks].sort((a, b) => String(b).length - String(a).length || b - a).join("|");
  const defaultFilter = `BM_AttrSigCombined_(Flat|Merkle)/(${nRegex})/(${kRegex})$`;
  const filter = process.env.BENCH_FILTER || defaultFilter;

  if (!args.compact) {
    console.log(`Backend: Longfellow (P-256 + SHA) — attr_commitment_experiment_test`);
    console.log(
      `Repetitions (outer samples): ${args.repetitions}  (BENCH_N / BENCH_REPETITIONS; --n / --repetitions)`
    );
    console.log(
      `Inner iterations per rep: ${args.iterations == null ? "adaptive (BENCH_ITERATIONS=auto or 0)" : args.iterations}  (BENCH_ITERATIONS; --iterations; default 1)`
    );
    console.log(`Totals: ${ns.join(", ")}  (env TOTAL_ATTRS; CLI --total-attrs / --attr)`);
    console.log(`Used:   ${ks.join(", ")}  (env USED_ATTRS; CLI --used-attrs / --used-attr)`);
    console.log(`Filter: ${filter}  (env BENCH_FILTER)`);
    console.log(`Metric: ${args.metric}   min_time: ${args.min_time}  (env BENCH_METRIC, BENCH_MIN_TIME)`);
    console.log(`Artifacts: ${args.outDir}  (env ARTIFACTS_DIR)`);
    console.log(
      `Cleanup before run: ${args.clean ? "enabled (--clean / CLEAN=1)" : "disabled"}`
    );
    console.log(
      `Cleanup after run: ${args.keepArtifacts ? "disabled (--keep-artifacts / KEEP_ARTIFACTS=1)" : "enabled (default; JSON summaries only)"}`
    );
    console.log(
      `Warm-up: ${benchWarmupEnabled() ? "1× Google Benchmark repetition discarded before measured run (BENCH_WARMUP=0 to skip)" : "disabled (BENCH_WARMUP)"}`
    );
    console.log("");
  }

  const benchBase = [
    `--benchmark_filter=${filter}`,
    `--benchmark_repetitions=${args.repetitions}`,
    "--benchmark_report_aggregates_only=false",
    "--benchmark_display_aggregates_only=false",
    `--benchmark_min_time=${formatBenchmarkMinTimeForGbench(args.min_time, args.bin)}`,
  ];
  if (args.iterations != null) {
    benchBase.push(`--benchmark_iterations=${args.iterations}`);
  }

  runGoogleBenchWarmup(args.bin, benchBase, { compact: args.compact });

  const gbenchJsonPath = path.join(
    os.tmpdir(),
    `longfellow-attr-gbench-${process.pid}-${Date.now()}.json`
  );
  const measuredArgs = [
    ...benchBase,
    "--benchmark_format=console",
    `--benchmark_out=${gbenchJsonPath}`,
    "--benchmark_out_format=json",
  ];

  if (!args.compact) {
    console.log(
      "[measured] Live Google Benchmark console follows; JSON for summaries is written to a temp file (--benchmark_out), then parsed when the binary exits.\n"
    );
  }

  const r = spawnSync(args.bin, measuredArgs, { stdio: "inherit" });
  if (r.error) throw r.error;

  let txt;
  try {
    txt = fs.readFileSync(gbenchJsonPath, "utf8");
  } catch (e) {
    console.error("Could not read Google Benchmark JSON output file:", gbenchJsonPath, e.message);
    process.exit(r.status ?? 1);
    return;
  } finally {
    try {
      fs.unlinkSync(gbenchJsonPath);
    } catch {
      /* ignore */
    }
  }

  const start = txt.indexOf("{");
  const end = txt.lastIndexOf("}");
  if (start < 0 || end < 0 || end <= start) {
    console.error("No JSON object found in --benchmark_out file (check binary exit status and filter).");
    process.exit(r.status ?? 1);
    return;
  }

  const json = JSON.parse(txt.slice(start, end + 1));
  const rows = json.benchmarks || [];
  const combinedByKey = collectCombinedSamples(rows, wantedN, wantedK);

  const merkleProver = new Map();
  const flatProver = new Map();
  const merkleVerifier = new Map();
  const flatVerifier = new Map();
  const rawByKey = {
    merkleProver: new Map(),
    flatProver: new Map(),
    merkleVerifier: new Map(),
    flatVerifier: new Map(),
  };

  let perRun = null;
  if (combinedByKey.size > 0) {
    for (const [, { mode, n, k, proveMs, verifyMs }] of combinedByKey.entries()) {
      const nkKey = `${n}/${k}`;
      const avgProver = mean(proveMs);
      const avgVerify = mean(verifyMs);
      const benchLabel = `BM_AttrSigCombined_${mode === "merkle" ? "Merkle" : "Flat"}/${n}/${k}`;
      if (mode === "merkle") {
        merkleProver.set(nkKey, avgProver);
        merkleVerifier.set(nkKey, avgVerify);
        rawByKey.merkleProver.set(benchLabel, proveMs);
        rawByKey.merkleVerifier.set(benchLabel, verifyMs);
      } else {
        flatProver.set(nkKey, avgProver);
        flatVerifier.set(nkKey, avgVerify);
        rawByKey.flatProver.set(benchLabel, proveMs);
        rawByKey.flatVerifier.set(benchLabel, verifyMs);
      }
    }
  } else {
    perRun = new Map();
    for (const b of rows) {
      if (b.aggregate_name) continue;
      const name = baseName(b.name || b.run_name || "");
      const meta = parseBenchName(name);
      if (!meta) continue;
      if (!wantedN.has(meta.n) || !wantedK.has(meta.k)) continue;
      const unit = String(b.time_unit || "ns");
      const v = Number(b[args.metric]);
      if (!Number.isFinite(v)) continue;
      const key = name;
      const cur = perRun.get(key) || { unit, values: [] };
      cur.unit = unit;
      cur.values.push(v);
      perRun.set(key, cur);
    }

    for (const [name, { unit, values }] of perRun.entries()) {
      const meta = parseBenchName(name);
      if (!meta || meta.kind === "combined") continue;
      const msValues = values.map((x) => toMs(x, unit)).filter((x) => x != null);
      if (!msValues.length) continue;
      const avgMs = mean(msValues);
      if (avgMs == null) continue;
      const key = `${meta.n}/${meta.k}`;
      if (meta.kind === "prover") {
        if (meta.mode === "merkle") {
          merkleProver.set(key, avgMs);
          rawByKey.merkleProver.set(name, msValues);
        } else {
          flatProver.set(key, avgMs);
          rawByKey.flatProver.set(name, msValues);
        }
      } else {
        if (meta.mode === "merkle") {
          merkleVerifier.set(key, avgMs);
          rawByKey.merkleVerifier.set(name, msValues);
        } else {
          flatVerifier.set(key, avgMs);
          rawByKey.flatVerifier.set(name, msValues);
        }
      }
    }
  }

  const metricLabel =
    combinedByKey.size > 0
      ? "prove_ns / verify_ns counters (wall clock)"
      : args.metric === "real_time"
        ? "real_time"
        : "cpu_time";

  if (VERBOSE) {
    console.log("\n── Per-benchmark sample stats (all matching runs) ──");
    for (const [name, msVals] of rawByKey.merkleProver) printStats(name, msVals);
    for (const [name, msVals] of rawByKey.flatProver) printStats(name, msVals);
    for (const [name, msVals] of rawByKey.merkleVerifier) printStats(name, msVals);
    for (const [name, msVals] of rawByKey.flatVerifier) printStats(name, msVals);
    console.log("");
  }

  printRecapGrid("Recap — Flat hash", flatProver, flatVerifier, ns, ks, metricLabel);
  printRecapGrid("Recap — Merkle", merkleProver, merkleVerifier, ns, ks, metricLabel);

  const summary = {
    meta: {
      type: "longfellow",
      N: args.repetitions,
      totals: ns,
      used: ks,
      timestampIso: new Date().toISOString(),
    },
    merkle: {},
    flat: {},
  };

  function fillSummaryBranch(branch, proverMap, verifyMap, modeLabel) {
    const mode = modeLabel.toLowerCase();
    for (const n of ns) {
      branch[n] = branch[n] || {};
      for (const k of ks) {
        if (k > n) continue;
        const nkKey = `${n}/${k}`;
        const comb = combinedByKey.get(`${mode}/${n}/${k}`);
        let successfulIters = null;
        if (comb) {
          successfulIters = comb.proveMs.length;
        } else if (perRun) {
          const proverBench = `BM_AttrSigProver_${modeLabel}/${n}/${k}`;
          const provEntry = perRun.get(proverBench);
          successfulIters = provEntry ? provEntry.values.length : null;
        }
        branch[n][k] = {
          avgProverMs: proverMap.get(nkKey) ?? null,
          avgVerifyMs: verifyMap.get(nkKey) ?? null,
          successfulIters,
        };
      }
    }
  }

  fillSummaryBranch(summary.merkle, merkleProver, merkleVerifier, "Merkle");
  fillSummaryBranch(summary.flat, flatProver, flatVerifier, "Flat");

  try {
    ensureDir(args.outDir);
    const ts = isoForFilename();
    fs.writeFileSync(path.join(args.outDir, `summary_${ts}.json`), JSON.stringify(summary, null, 2));
    fs.writeFileSync(path.join(args.outDir, "summary_latest.json"), JSON.stringify(summary, null, 2));
  } catch (e) {
    console.error("Could not write summary JSON:", e.message);
  }

  if (!args.compact) {
    console.log(
      `Summary written: ${path.join(args.outDir, "summary_latest.json")}` +
        (args.keepArtifacts ? " (out-dir kept)" : "")
    );
  }

  if (!merkleProver.size && !flatProver.size) {
    console.error("No benchmark data parsed (check filter vs registered n/k in the binary).");
    process.exit(1);
  }
  if (r.status !== 0 && r.status != null) {
    console.error(
      `Note: benchmark process exited with code ${r.status} (JSON parsed; summary written if applicable).`
    );
  }

  process.exit(0);
}

try {
  main();
} catch (e) {
  console.error(e);
  process.exit(1);
}
