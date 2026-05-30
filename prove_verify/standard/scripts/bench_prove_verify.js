#!/usr/bin/env node
"use strict";

/**
 * Longfellow (Google Benchmark) driver for the "prove + verify" credential
 * commitment circuit (CFT variant): flat SHA-256 over 32 attribute slots,
 * 7 disclosed (indices 0,1,4,5,6,14,15). The no-CFT counterpart lives in
 * `bench_prove_verify_no_cft.js`. The matching zk-friendly Circom benchmark
 * is `prove_verify/zk-friendly/prove_verify/bench_prove_verify.js`.
 *
 * Environment:
 *   BENCH_N               Outer repetitions → --benchmark_repetitions (default 20). Alias: BENCH_REPETITIONS.
 *   BENCH_ITERATIONS      Inner iterations per repetition → --benchmark_iterations (default 1). auto/0 = adaptive (min_time).
 *   BENCH_MIN_TIME        Passed through (default 0.05s).
 *   BENCH_FILTER          Regex filter (default BM_ProveVerify(Prover|Verifier|FullCycle)_P256.*).
 *   BENCH_METRIC          real_time | cpu_time | both — controls --verbose printStats only (default both).
 *   ARTIFACTS_DIR         Directory name (under prove_verify/standard/) or absolute path for summary JSON.
 *                         Default: artifacts_bench_prove_verify.
 *   LONGFELLOW_CRED_BENCH_BIN   Path to prove_verify_test if not using the default build path.
 *   KEEP_ARTIFACTS        Set with --keep-artifacts to disable any extra cleanup (summaries are always kept).
 *   CLEAN                 Set with --clean to delete ARTIFACTS_DIR before the run.
 *   BENCH_WARMUP          0/false/no: skip the 1× discarded Google Benchmark warm-up run (default: on).
 *
 * Flags (thesis-aligned):
 *   --verbose               after the run: printStats lines (warm-up + measured: live GB console; JSON from temp file parsed after measured pass)
 *   --quiet                 compatibility no-op (quiet console is default)
 *   --compact               minimal header
 *   --keep-artifacts        same as env KEEP_ARTIFACTS=1
 *   --clean                 same as env CLEAN=1: wipe artifacts dir before run
 *   --bin PATH
 *   --filter REGEX
 *   --n N / --repetitions N   → BENCH_N
 *   --iterations N | auto     → BENCH_ITERATIONS (default 1; auto = adaptive inner loop)
 *   --min_time 0.2s
 *   --metric real_time|cpu_time|both
 *   --out-dir DIR           override ARTIFACTS_DIR (absolute or cwd-relative)
 *   --help, -h
 */
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

/** Parent of `scripts/` — `prove_verify/standard` locally and `/bench` in the Docker image. */
const STANDARD_ROOT = path.join(__dirname, "..");
/** Longfellow C++ tree: `longfellow-zk/` when present; otherwise same as STANDARD_ROOT (flat `/bench` layout in Docker). */
const LONGFELLOW_ROOT = fs.existsSync(path.join(STANDARD_ROOT, "longfellow-zk", "lib", "CMakeLists.txt"))
  ? path.join(STANDARD_ROOT, "longfellow-zk")
  : STANDARD_ROOT;

function resolveArtifactsDir(defaultSubdir) {
  const raw = process.env.ARTIFACTS_DIR;
  if (!raw) return path.join(STANDARD_ROOT, defaultSubdir);
  return path.isAbsolute(raw) ? raw : path.join(STANDARD_ROOT, raw);
}

function printUsage(prog) {
  console.log(`Usage: node ${path.basename(prog)} [options]

Environment (thesis-style):
  BENCH_N               Outer repetitions (statistical samples). Default 20.
  BENCH_REPETITIONS     Alias for BENCH_N.
  BENCH_ITERATIONS      Inner iterations per repetition (default 1). auto or 0 = adaptive from min_time.
  BENCH_MIN_TIME        e.g. 0.05s, 0.2s
  BENCH_FILTER          Regex, default BM_ProveVerify(Prover|Verifier|FullCycle)_P256.*
  BENCH_METRIC          real_time | cpu_time | both (verbose printStats)
  ARTIFACTS_DIR         Subdir under prove_verify/standard or absolute path for summaries
  LONGFELLOW_CRED_BENCH_BIN   Path to benchmark binary
  KEEP_ARTIFACTS=1      With --keep-artifacts
  CLEAN=1               With --clean: remove artifact dir before run
  BENCH_WARMUP=0        Skip the extra 1× repetition warm-up run before measurement

Flags:
  --verbose  After run: printStats (measured pass shows live GB console; JSON read from temp --benchmark_out file)
  --quiet  --compact  --keep-artifacts  --clean
  --bin PATH  --filter REGEX  --n N  --repetitions N  --iterations N|auto  --min_time T  --metric M  --out-dir DIR
  -h, --help
`);
}

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

function statsForSummary(arrMs) {
  if (!arrMs || !arrMs.length) return null;
  const s = stats(arrMs);
  if (!s) return null;
  return {
    minMs: s.min,
    maxMs: s.max,
    avgMs: s.avg,
    p95Ms: s.p95,
  };
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

function defaultBinPath() {
  return path.join(
    LONGFELLOW_ROOT,
    "clang-build-release",
    "circuits",
    "tests",
    "ec",
    "prove_verify_test"
  );
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

function classifyBench(base) {
  // The no-CFT benchmarks share the BM_ProveVerify prefix, so anchor on the
  // tail to avoid misclassifying them.
  if (/^BM_ProveVerifyFullCycle/.test(base)) return "fullCycle";
  if (/^BM_ProveVerifyVerifier/.test(base)) return "verifyOnly";
  if (/^BM_ProveVerifyProver/.test(base)) return "prover";
  return "other";
}

function parseArgs(argv) {
  const repEnv = process.env.BENCH_N ?? process.env.BENCH_REPETITIONS ?? "20";
  const out = {
    bin: process.env.LONGFELLOW_CRED_BENCH_BIN || null,
    // Default filter excludes the no-CFT benchmarks (which start with
    // BM_ProveVerifyNoCft) by anchoring on the suffix kind.
    filter: process.env.BENCH_FILTER || "BM_ProveVerify(Prover|Verifier|FullCycle)_P256.*",
    repetitions: Number(repEnv, 10) || 20,
    min_time: process.env.BENCH_MIN_TIME || "0.05s",
    metric: process.env.BENCH_METRIC || "both",
    verbose: argv.includes("--verbose"),
    compact: argv.includes("--compact"),
    keepArtifacts: argv.includes("--keep-artifacts") || process.env.KEEP_ARTIFACTS === "1",
    clean: argv.includes("--clean") || process.env.CLEAN === "1",
    outDir: resolveArtifactsDir("artifacts_bench_prove_verify"),
    iterations: parseBenchInnerIterationsFromEnv(),
  };

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const v = argv[i + 1];
    if (a === "--bin") out.bin = v, i++;
    else if (a === "--filter") out.filter = v, i++;
    else if (a === "--repetitions" || a === "--n") out.repetitions = Number(v), i++;
    else if (a === "--iterations") out.iterations = parseIterationsCli(v), i++;
    else if (a === "--min_time") out.min_time = v, i++;
    else if (a === "--metric") out.metric = v, i++;
    else if (a === "--out-dir") out.outDir = path.resolve(v), i++;
    else if (a === "--verbose") out.verbose = true;
    else if (a === "--compact") out.compact = true;
    else if (a === "--keep-artifacts") out.keepArtifacts = true;
    else if (a === "--clean") out.clean = true;
    else if (a === "--quiet") {
      /* thesis: quiet default; flag is a no-op */
    } else if (a === "--help" || a === "-h") {
      printUsage(argv[1] || "bench_prove_verify.js");
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
      `Benchmark binary not found at ${d}. Build first (from prove_verify/standard/longfellow-zk: cmake -S lib -B clang-build-release && cmake --build clang-build-release -j), or set LONGFELLOW_CRED_BENCH_BIN / pass --bin PATH`
    );
  }
  if (!["real_time", "cpu_time", "both"].includes(out.metric)) {
    throw new Error("--metric must be real_time, cpu_time, or both");
  }
  if (!Number.isFinite(out.repetitions) || out.repetitions < 1) {
    throw new Error("--n / --repetitions / BENCH_N must be >= 1");
  }
  return out;
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

  if (!args.compact) {
    console.log(`Backend: Longfellow — prove_verify_test (32 attrs, flat SHA, 7 used; CFT variant)`);
    console.log(`Repetitions (outer samples): ${args.repetitions}  (BENCH_N / BENCH_REPETITIONS; --n / --repetitions)`);
    console.log(
      `Inner iterations per rep: ${args.iterations == null ? "adaptive (BENCH_ITERATIONS=auto or 0)" : args.iterations}  (BENCH_ITERATIONS; --iterations; default 1)`
    );
    console.log(`Filter: ${args.filter}  (env BENCH_FILTER)`);
    console.log(`min_time: ${args.min_time}  (env BENCH_MIN_TIME)`);
    console.log(`Metric (verbose only): ${args.metric}  (env BENCH_METRIC)`);
    console.log(`Artifacts: ${args.outDir}  (env ARTIFACTS_DIR; default under prove_verify/standard)`);
    console.log(
      `Cleanup after run: ${args.keepArtifacts ? "disabled (--keep-artifacts / KEEP_ARTIFACTS=1)" : "enabled (default; JSON summaries only)"}`
    );
    console.log(
      `Warm-up: ${benchWarmupEnabled() ? "1× Google Benchmark repetition discarded before measured run (BENCH_WARMUP=0 to skip)" : "disabled (BENCH_WARMUP)"}`
    );
    console.log("");
  }

  const benchBase = [
    `--benchmark_filter=${args.filter}`,
    `--benchmark_repetitions=${args.repetitions}`,
    `--benchmark_report_aggregates_only=false`,
    `--benchmark_display_aggregates_only=false`,
    `--benchmark_min_time=${args.min_time}`,
  ];
  if (args.iterations != null) {
    benchBase.push(`--benchmark_iterations=${args.iterations}`);
  }

  runGoogleBenchWarmup(args.bin, benchBase, { compact: args.compact });

  const gbenchJsonPath = path.join(
    os.tmpdir(),
    `longfellow-cred-gbench-${process.pid}-${Date.now()}.json`
  );
  const measuredArgs = [
    ...benchBase,
    "--benchmark_format=console",
    `--benchmark_out=${gbenchJsonPath}`,
    "--benchmark_out_format=json",
  ];

  if (!args.compact) {
    console.log(
      "[measured] Live Google Benchmark console follows; JSON for summaries is read from a temp file (--benchmark_out) when the binary exits.\n"
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
  const perRun = new Map();

  for (const b of rows) {
    const name = String(b.name || b.run_name || "");
    if (b.aggregate_name) continue;
    if (!name) continue;
    const base = baseName(name);
    const cpu = Number(b.cpu_time);
    const real = Number(b.real_time);
    const unit = String(b.time_unit || "ns");
    if (!Number.isFinite(cpu) || !Number.isFinite(real)) continue;

    const cur = perRun.get(base) || { cpu: [], real: [], unit };
    cur.cpu.push(cpu);
    cur.real.push(real);
    cur.unit = unit;
    perRun.set(base, cur);
  }

  const names = [...perRun.keys()].sort();
  if (names.length === 0) {
    console.log("No benchmark samples found (check --filter).");
    process.exit(1);
  }

  const byKind = {
    prover: { bases: [] },
    verifyOnly: { bases: [] },
    fullCycle: { bases: [] },
  };
  for (const base of names) {
    const k = classifyBench(base);
    if (k === "other") continue;
    byKind[k].bases.push(base);
  }

  if (VERBOSE) {
    console.log("── Results (printStats) ──");
    const wantCpu = args.metric === "both" || args.metric === "cpu_time";
    const wantReal = args.metric === "both" || args.metric === "real_time";
    for (const base of names) {
      const { cpu, real, unit } = perRun.get(base);
      if (wantCpu) printStats(`${base} cpu`, cpu.map((x) => toMs(x, unit)));
      if (wantReal) printStats(`${base} real`, real.map((x) => toMs(x, unit)));
    }
    console.log("");
  }

  const summary = {
    meta: {
      type: "longfellow-p256-sha-credential",
      variant: "prove_verify",
      backend: "prove_verify_test",
      bin: args.bin,
      bench_n: args.repetitions,
      benchmark_iterations: args.iterations,
      filter: args.filter,
      repetitions: args.repetitions,
      min_time: args.min_time,
      metric: args.metric,
      artifacts_dir: args.outDir,
      timestampIso: new Date().toISOString(),
      warmup_repetitions_discarded: benchWarmupEnabled() ? 1 : 0,
    },
    byBenchmark: {},
    rollup: {},
  };

  for (const base of names) {
    const { cpu, real, unit } = perRun.get(base);
    const cpuMs = cpu.map((x) => toMs(x, unit));
    const realMs = real.map((x) => toMs(x, unit));
    summary.byBenchmark[base] = {
      statsMs: {
        cpu_time: statsForSummary(cpuMs),
        real_time: statsForSummary(realMs),
      },
      kind: classifyBench(base),
    };
  }

  for (const kind of ["prover", "verifyOnly", "fullCycle"]) {
    const bases = byKind[kind].bases;
    if (!bases.length) continue;
    const pick = bases[0];
    const { cpu, real, unit } = perRun.get(pick);
    const cpuMs = cpu.map((x) => toMs(x, unit));
    const realMs = real.map((x) => toMs(x, unit));
    summary.rollup[kind] = {
      benchmark: pick,
      statsMs: {
        cpu_time: statsForSummary(cpuMs),
        real_time: statsForSummary(realMs),
      },
    };
  }

  try {
    ensureDir(args.outDir);
    const ts = isoForFilename();
    fs.writeFileSync(path.join(args.outDir, `summary_${ts}.json`), JSON.stringify(summary, null, 2));
    fs.writeFileSync(path.join(args.outDir, "summary_latest.json"), JSON.stringify(summary, null, 2));
  } catch (e) {
    console.error("Could not write summary JSON:", e.message);
  }

  const summaryPath = path.join(args.outDir, "summary_latest.json");
  console.log(
    `Summary written: ${summaryPath}` + (args.keepArtifacts ? " (KEEP_ARTIFACTS)" : "")
  );

  if (r.status !== 0 && r.status != null) {
    console.error(`Note: benchmark process exited with code ${r.status} (JSON parsed; summary written).`);
  }

  process.exit(0);
}

try {
  main();
} catch (e) {
  console.error(e);
  process.exit(1);
}
