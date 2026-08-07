"use strict";

const { spawnSync } = require("child_process");

/** Shared Google Benchmark JSON helpers for Longfellow presentation benches. */

const minTimeFormatCache = new Map();

function parseBenchmarkMinTimeSeconds(raw) {
  const t = String(raw ?? "0.05").trim();
  if (/^[\d.]+ms$/i.test(t)) return parseFloat(t) / 1000;
  if (/^[\d.]+us$/i.test(t)) return parseFloat(t) / 1e6;
  if (/^[\d.]+s$/i.test(t)) return parseFloat(t);
  if (/^[\d.]+$/.test(t)) return parseFloat(t);
  throw new Error(`Invalid BENCH_MIN_TIME / --min_time: ${raw}`);
}

function formatBenchmarkMinTimeForMeta(raw) {
  const sec = parseBenchmarkMinTimeSeconds(raw);
  return `${sec}s`;
}

function detectBenchmarkMinTimeFormat(bin) {
  const forced = String(process.env.BENCH_MIN_TIME_FORMAT || "").trim().toLowerCase();
  if (forced === "plain" || forced === "suffix") return forced;
  if (!bin) return "plain";

  const cached = minTimeFormatCache.get(bin);
  if (cached) return cached;

  const r = spawnSync(
    bin,
    ["--benchmark_min_time=0.001s", "--benchmark_list_tests"],
    { encoding: "utf8", timeout: 10000 }
  );
  const out = `${r.stdout || ""}\n${r.stderr || ""}`;
  const format = /expected to be a double/i.test(out) ? "plain" : "suffix";
  minTimeFormatCache.set(bin, format);
  return format;
}

function formatBenchmarkMinTimeForGbench(raw, bin) {
  const sec = parseBenchmarkMinTimeSeconds(raw);
  return detectBenchmarkMinTimeFormat(bin) === "suffix" ? `${sec}s` : String(sec);
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

function statsForSummary(arrMs) {
  if (!arrMs || !arrMs.length) return null;
  const s = stats(arrMs);
  if (!s) return null;
  return { minMs: s.min, maxMs: s.max, avgMs: s.avg, p95Ms: s.p95, medianMs: s.median };
}

/**
 * One BM pass per repetition: prove_ns + verify_ns counters (steady_clock, wall time).
 * Returns null if no combined rows found.
 *
 * Longfellow has no witness/prove split: prove_ns → proverTotal.
 */
function rollupFromCombinedCounters(rows) {
  const proveMs = [];
  const verifyMs = [];
  let combinedBase = null;

  for (const b of rows) {
    if (b.aggregate_name) continue;
    const name = String(b.name || b.run_name || "");
    if (!/Combined/.test(name)) continue;
    const proveNs = Number(b.prove_ns);
    const verifyNs = Number(b.verify_ns);
    if (!Number.isFinite(proveNs) || !Number.isFinite(verifyNs)) continue;
    if (!combinedBase) combinedBase = name.replace(/\/repetition:\d+$/, "").replace(/\/repeat:\d+$/, "");
    proveMs.push(proveNs / 1e6);
    verifyMs.push(verifyNs / 1e6);
  }

  if (!proveMs.length) return null;

  const fullMs = proveMs.map((p, i) => p + verifyMs[i]);
  return {
    combinedBase,
    proveMs,
    verifyMs,
    fullMs,
  };
}

/**
 * zk-friendly-shaped timing summary (no witness/prove split for Longfellow).
 * metaExtra is merged into meta after the common fields.
 */
function buildTimingSummaryFromCombined(rows, metaExtra = {}) {
  const combined = rollupFromCombinedCounters(rows);
  if (!combined) return null;

  const proverTotal = statsForSummary(combined.proveMs);
  const verify = statsForSummary(combined.verifyMs);
  const fullCycle = statsForSummary(combined.fullMs);
  const successfulIters = combined.proveMs.length;

  return {
    meta: {
      ...metaExtra,
      N: metaExtra.N ?? successfulIters,
      timestampIso: metaExtra.timestampIso || new Date().toISOString(),
    },
    results: { successfulIters },
    avgMs: {
      proverTotal: proverTotal?.avgMs ?? null,
      verify: verify?.avgMs ?? null,
    },
    statsMs: {
      proverTotal,
      verify,
      fullCycle,
    },
  };
}

module.exports = {
  buildTimingSummaryFromCombined,
  formatBenchmarkMinTimeForGbench,
  formatBenchmarkMinTimeForMeta,
  parseBenchmarkMinTimeSeconds,
  rollupFromCombinedCounters,
  statsForSummary,
};
