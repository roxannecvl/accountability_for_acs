"use strict";

// Helpers to compile a .mpc program and run MP-SPDZ's shamir-party.x.
// All functions are pure orchestration — no protocol logic.

const { spawn } = require("child_process");
const fsp = require("fs/promises");
const path = require("path");

function spawnCapture(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, opts);
    let out = "", err = "";
    p.stdout.on("data", (c) => (out += c.toString()));
    p.stderr.on("data", (c) => (err += c.toString()));
    p.on("exit", (code) => {
      if (code === 0) resolve({ out, err });
      else reject(new Error(`${cmd} ${args.join(" ")} exit ${code}\nstderr:\n${err}\nstdout:\n${out}`));
    });
  });
}

async function compileMpc({ spdzPath, mpcSrcPath, name, args }) {
  const srcDir = path.join(spdzPath, "Programs", "Source");
  await fsp.mkdir(srcDir, { recursive: true });
  await fsp.copyFile(mpcSrcPath, path.join(srcDir, `${name}.mpc`));

  const fullName = [name, ...args].join("-");
  const schPath  = path.join(spdzPath, "Programs", "Schedules", `${fullName}.sch`);
  try {
    await fsp.access(schPath);
    console.log(`[mpc] cached compile for ${fullName}`);
    return fullName;
  } catch (_) { /* not cached → compile */ }

  console.log(`[mpc] compiling ${name} ${args.join(" ")} ...`);
  const t0 = Date.now();
  await spawnCapture("./compile.py", [name, ...args.map(String)], { cwd: spdzPath });
  console.log(`[mpc] ✓ compile done (${Date.now() - t0} ms) → ${fullName}.sch`);
  return fullName;
}

async function runMpc({ spdzPath, fullName, T = 3, binary = "mascot-party.x" }) {
  console.log(`[mpc] launching ${T} parties: ${binary} ${fullName}`);
  const t0 = Date.now();
  const procs = [];
  const outs = new Array(T).fill("");
  const errs = new Array(T).fill("");
  for (let i = 0; i < T; i++) {
    const p = spawn(`./${binary}`,
      ["-v", "-N", String(T), "-p", String(i), fullName],
      { cwd: spdzPath });
    p.stdout.on("data", (c) => { outs[i] += c.toString(); });
    p.stderr.on("data", (c) => { errs[i] += c.toString(); });
    procs.push(p);
  }
  const codes = await Promise.all(procs.map((p) => new Promise((r) => p.on("exit", r))));
  console.log(`[mpc] ✓ done in ${Date.now() - t0} ms (codes: [${codes.join(",")}])`);
  if (codes.some((c) => c !== 0)) {
    throw new Error(`MP-SPDZ failed.\nstderr (p0):\n${errs[0]}\nstdout (p0):\n${outs[0]}`);
  }
  return { stdouts: outs, stderrs: errs };
}

function parsePredicates(stdout, N) {
  const out = new Array(N).fill(null);
  for (const line of stdout.split("\n")) {
    const m = line.match(/^row_(\d+)=(\d)/);
    if (m) out[parseInt(m[1], 10)] = m[2] === "1";
  }
  if (out.some((v) => v === null)) {
    throw new Error(`failed to parse all ${N} predicate rows from MP-SPDZ stdout`);
  }
  return out;
}

// ── MP-SPDZ stderr parser (extracts online/offline timing and bandwidth) ────
// MP-SPDZ writes timing diagnostics to stderr when run with -v.
function parseSpdzStats(combined) {
  const out = {
    spdz_total_ms: null,
    spdz_online_ms: null,
    spdz_offline_ms: null,
    spdz_online_bytes: null,
    spdz_online_rounds: null,
    spdz_offline_bytes: null,
    spdz_offline_rounds: null,
    spdz_data_sent_bytes: null,
    spdz_data_sent_rounds: null,
    spdz_global_data_sent_bytes: null,
  };
  const fSec = (s) => parseFloat(s) * 1000;
  const toBytes = (n, unit) => {
    const v = parseFloat(n);
    const u = (unit || "").toLowerCase();
    if (u.startsWith("g")) return Math.round(v * 1024 ** 3);
    if (u.startsWith("m")) return Math.round(v * 1024 ** 2);
    if (u.startsWith("k")) return Math.round(v * 1024);
    return Math.round(v);
  };

  let m;
  m = combined.match(/\bTime\s*=\s*([\d.]+)(?:\s*seconds?)?\b/);
  if (m) out.spdz_total_ms = fSec(m[1]);
  m = combined.match(/\bTime1\s*=\s*([\d.]+)(?:\s*seconds?)?\b/);
  if (m) out.spdz_online_ms = fSec(m[1]);

  m = combined.match(
    /Spent\s+([\d.]+)\s*seconds?\s*\(([\d.]+)\s*([kKmMgG]?B),\s*(\d+)\s*rounds?\)\s*on\s*the\s*online\s*phase\s*and\s*([\d.]+)\s*seconds?\s*\(([\d.]+)\s*([kKmMgG]?B),\s*(\d+)\s*rounds?\)\s*on\s*the\s*preprocessing(?:\/offline)?\s*phase/i
  );
  if (m) {
    out.spdz_online_ms      = fSec(m[1]);
    out.spdz_online_bytes   = toBytes(m[2], m[3]);
    out.spdz_online_rounds  = parseInt(m[4], 10);
    out.spdz_offline_ms     = fSec(m[5]);
    out.spdz_offline_bytes  = toBytes(m[6], m[7]);
    out.spdz_offline_rounds = parseInt(m[8], 10);
  }

  m = combined.match(/Data sent\s*=\s*([\d.]+)\s*([kKmMgG]?B)\s*in\s*~?(\d+)\s*rounds?/);
  if (m) {
    out.spdz_data_sent_bytes  = toBytes(m[1], m[2]);
    out.spdz_data_sent_rounds = parseInt(m[3], 10);
  }
  m = combined.match(/Global data sent\s*=\s*([\d.]+)\s*([kKmMgG]?B)/);
  if (m) out.spdz_global_data_sent_bytes = toBytes(m[1], m[2]);

  return out;
}

// ── CSV writer ────────────────────────────────────────────────────────────
function appendCsv(filePath, row, columnOrder) {
  const fs = require("fs");
  const path = require("path");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const exists = fs.existsSync(filePath);
  const esc = (v) => {
    if (v == null) return "";
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const cols = columnOrder || Object.keys(row);
  const line = cols.map((c) => esc(row[c])).join(",");
  if (!exists) {
    fs.writeFileSync(filePath, cols.join(",") + "\n" + line + "\n");
  } else {
    fs.appendFileSync(filePath, line + "\n");
  }
}

module.exports = { compileMpc, runMpc, parsePredicates, spawnCapture, parseSpdzStats, appendCsv };
