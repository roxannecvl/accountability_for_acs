"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// circom include path: <this folder>/../node_modules
const DEFAULT_CIRCOM_LIB_PATH = path.resolve(__dirname, "..", "node_modules");

/** CLI used by `ensureGroth16ZkeyAndVkey` (not the in-process `require("snarkjs")` verifier). */
function getSnarkjsCliForShell() {
  if (process.env.SNARKJS_BIN) return process.env.SNARKJS_BIN;
  const local = path.resolve(__dirname, "..", "node_modules", ".bin", "snarkjs");
  if (fs.existsSync(local)) return local;
  return "snarkjs";
}

function snarkjsCliToken() {
  const b = getSnarkjsCliForShell();
  return b === "snarkjs" ? b : JSON.stringify(b);
}

function setupProgress(msg) {
  if (process.env.BENCH_SILENT_SETUP === "1") return;
  console.log(msg);
}

function createZkUtils(baseDir) {
  if (!baseDir) throw new Error("createZkUtils: baseDir is required");

  function resolvePath(p) {
    return path.isAbsolute(p) ? p : path.resolve(baseDir, p);
  }

  function exec(cmd, opts = {}) {
    try {
      const stdout = execSync(cmd, { cwd: baseDir, stdio: ["ignore", "pipe", "pipe"], ...opts });
      return { ok: true, stdout: stdout?.toString() ?? "", stderr: "" };
    } catch (e) {
      return {
        ok: false,
        stdout: e.stdout?.toString?.() ?? "",
        stderr: e.stderr?.toString?.() ?? String(e),
        code: e.status ?? 1,
      };
    }
  }

  function nowNs() {
    return process.hrtime.bigint();
  }

  function nsToMs(ns) {
    return Number(ns) / 1e6;
  }

  function ensureDir(dirPath) {
    fs.mkdirSync(resolvePath(dirPath), { recursive: true });
  }

  function writeJson(filePath, obj) {
    fs.writeFileSync(resolvePath(filePath), JSON.stringify(obj, null, 2));
  }

  function section(title) {
    console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log(`  ${title}`);
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  }

  return {
    baseDir,
    resolvePath,
    exec,
    nowNs,
    nsToMs,
    ensureDir,
    writeJson,
    section,
  };
}

function ensureRapidsnarkAvailable(zk, rapidsnarkBin) {
  const isPathLike = String(rapidsnarkBin).includes("/");
  if (isPathLike) {
    try {
      fs.accessSync(rapidsnarkBin, fs.constants.X_OK);
    } catch {
      throw new Error(`rapidsnark binary not found or not executable at path: ${rapidsnarkBin}`);
    }
    return;
  }

  const which = zk.exec(`command -v ${rapidsnarkBin}`);
  if (!which.ok || !which.stdout.trim()) {
    throw new Error(
      [
        `rapidsnark not found in PATH (looked for '${rapidsnarkBin}').`,
        "Install rapidsnark, or point to it via RAPIDSNARK_BIN.",
        "Example:",
        `  RAPIDSNARK_BIN=/absolute/path/to/prover node <script>`,
      ].join("\n")
    );
  }
}

function resolveCircomBin(circomBin) {
  const requested = circomBin || process.env.CIRCOM_BIN || process.env.CIRCOM;
  if (requested) return requested;
  return "circom";
}

function assertExecutableIfPath(cmd) {
  const isPathLike = String(cmd).includes("/");
  if (!isPathLike) return;
  try {
    fs.accessSync(cmd, fs.constants.X_OK);
  } catch {
    throw new Error(`circom binary not found or not executable at path: ${cmd}`);
  }
}

function ensureCircuitCompiled(zk, { circomFile, r1csFile, symFile, outDir = ".", circomBin } = {}) {
  if (!circomFile) throw new Error("ensureCircuitCompiled: circomFile is required");
  if (!r1csFile) throw new Error("ensureCircuitCompiled: r1csFile is required");
  if (!symFile) {
    symFile = String(r1csFile).replace(/\.r1cs$/i, ".sym");
  }

  const circomAbs = zk.resolvePath(circomFile);
  const r1csAbs = zk.resolvePath(r1csFile);
  const symAbs = zk.resolvePath(symFile);

  const r1csOk = fs.existsSync(r1csAbs);
  const symOk = fs.existsSync(symAbs);
  if (r1csOk && symOk) {
    let srcMtime = 0;
    try {
      srcMtime = fs.statSync(circomAbs).mtimeMs;
    } catch {
      srcMtime = 0;
    }
    let outMtime = Infinity;
    try {
      outMtime = Math.min(fs.statSync(r1csAbs).mtimeMs, fs.statSync(symAbs).mtimeMs);
    } catch {
      outMtime = -Infinity;
    }
    if (srcMtime <= outMtime) {
      setupProgress("  [setup] Using cached R1CS/sym (skipped circom compile).");
      return;
    }
  }

  zk.section("Setup (Compiling circuit)");
  setupProgress("  [setup] Compiling circuit (circom)...");
  const circomCmd = resolveCircomBin(circomBin);
  assertExecutableIfPath(circomCmd);
  zk.ensureDir(outDir);
  const compile = zk.exec(
    `"${circomCmd}" ${path.basename(circomFile)} --r1cs --sym -o ${outDir} -l "${DEFAULT_CIRCOM_LIB_PATH}"`
  );
  if (!compile.ok) throw new Error(compile.stderr || compile.stdout);
}

function ensureCppWitnessGenerator(zk, { circomFile, outDir = ".", circomBin } = {}) {
  if (!circomFile) throw new Error("ensureCppWitnessGenerator: circomFile is required");

  const circomAbs = zk.resolvePath(circomFile);
  const circuitName = path.basename(circomFile).replace(/\.circom$/i, "");
  const cppDirRel = path.join(outDir, `${circuitName}_cpp`);
  const cppDirAbs = zk.resolvePath(cppDirRel);
  const binRel = path.join(cppDirRel, circuitName);
  const binAbs = zk.resolvePath(binRel);
  const datAbs = path.join(cppDirAbs, `${circuitName}.dat`);

  const binOk = fs.existsSync(binAbs);
  const datOk = fs.existsSync(datAbs);
  if (binOk && datOk) {
    try {
      const srcM = fs.statSync(circomAbs).mtimeMs;
      const binM = fs.statSync(binAbs).mtimeMs;
      const datM = fs.statSync(datAbs).mtimeMs;
      if (binM >= srcM && datM >= srcM) {
        setupProgress("  [setup] Using cached C++ witness binary (skipped make).");
        return { cppDir: cppDirRel, witnessBin: binRel };
      }
    } catch {
      // fall through
    }
  }

  zk.section("Setup (Building C++ witness generator)");
  setupProgress("  [setup] Building C++ witness generator (circom --c + make)...");
  const circomCmd = resolveCircomBin(circomBin);
  assertExecutableIfPath(circomCmd);

  const gen = zk.exec(
    `"${circomCmd}" ${path.basename(circomFile)} --c --no_asm -o ${outDir} -l "${DEFAULT_CIRCOM_LIB_PATH}"`
  );
  if (!gen.ok) throw new Error(gen.stderr || gen.stdout);

  // Best-effort: ensure Homebrew include/lib paths are used on macOS.
  // Circom's generated Makefiles don't add brew's prefix, so headers like
  // nlohmann/json.hpp (installed via `brew install nlohmann-json`) may not be found.
  try {
    patchCircomCppMakefileForBrew(zk, path.join(cppDirAbs, "Makefile"));
    patchCircomFrBackendForDarwin(cppDirAbs);
  } catch {
    // best-effort only
  }

  const mk = zk.exec(`make -C ${cppDirRel}`);
  if (!mk.ok) {
    const msg = mk.stderr || mk.stdout || "make failed";
    throw new Error(
      [
        msg,
        "",
        "If this is a missing dependency on macOS, try:",
        "  brew install gmp nlohmann-json",
      ].join("\n")
    );
  }

  try {
    fs.accessSync(binAbs, fs.constants.X_OK);
  } catch {
    throw new Error(`C++ witness binary not found or not executable at: ${binAbs}`);
  }

  return { cppDir: cppDirRel, witnessBin: binRel };
}

function patchCircomCppMakefileForBrew(zk, mkPath) {
  if (process.platform !== "darwin") return;
  if (!fs.existsSync(mkPath)) return;

  let mkText = fs.readFileSync(mkPath, "utf8");

  // Detect brew prefix (works for both Intel and Apple Silicon).
  const brewWhich = zk.exec("command -v brew");
  const hasBrew = brewWhich.ok && String(brewWhich.stdout || "").trim().length > 0;
  if (!hasBrew) return;

  // Inject BREW_PREFIX and include/lib flags once.
  if (!mkText.includes("BREW_PREFIX") && mkText.includes("CFLAGS=")) {
    mkText = mkText.replace(
      /^(CFLAGS=.*)$/m,
      [
        "$1",
        "BREW_PREFIX ?= $(shell brew --prefix 2>/dev/null)",
        "CFLAGS += -I$(BREW_PREFIX)/include",
        "LDFLAGS += -L$(BREW_PREFIX)/lib",
      ].join("\n")
    );
  }

  // Ensure link steps that use -lgmp also use $(LDFLAGS).
  mkText = mkText
    .split("\n")
    .map((line) => {
      if (!line.includes("-lgmp")) return line;
      if (!line.includes("$(CC)")) return line;
      if (line.includes("$(LDFLAGS)")) return line;
      return line.replace(/\$\(CC\)\s+/, "$(CC) $(LDFLAGS) ");
    })
    .join("\n");

  fs.writeFileSync(mkPath, mkText);
}

function patchCircomFrBackendForDarwin(cppDirAbs) {
  if (process.platform !== "darwin") return;

  // Circom's `--no_asm` backend uses GMP's `mpn_*` APIs. On macOS/Homebrew,
  // `mp_limb_t` is typically `unsigned long` while `uint64_t` is often
  // `unsigned long long`; Clang rejects passing `uint64_t*` to `mpn_*`.
  //
  // Patch generated `fr.hpp` / `fr.cpp` to use `mp_limb_t` for limb arrays.

  const frHppPath = path.join(cppDirAbs, "fr.hpp");
  if (fs.existsSync(frHppPath)) {
    let frHpp = fs.readFileSync(frHppPath, "utf8");
    let changed = false;

    const next = frHpp
      .replace(/typedef\s+uint64_t\s+FrRawElement\[Fr_N64\];/g, "typedef mp_limb_t FrRawElement[Fr_N64];")
      .replace(/\buint64_t\s+pRawB\b/g, "mp_limb_t pRawB");
    if (next !== frHpp) {
      frHpp = next;
      changed = true;
    }

    // Some generated fr.hpp uses non-standard `uint` without typedef on macOS.
    const needsUintTypedef = frHpp.includes("uint base") && !frHpp.includes("<sys/types.h>");
    if (needsUintTypedef) {
      const appleBlock = "\n#ifdef __APPLE__\n#include <sys/types.h> // typedef unsigned int uint;\n#endif // __APPLE__\n";
      if (frHpp.includes("#include <gmp.h>")) {
        frHpp = frHpp.replace("#include <gmp.h>", `#include <gmp.h>${appleBlock}`);
      } else {
        frHpp = frHpp.replace(/^(#include[^\n]*\n)/m, `$1${appleBlock}\n`);
      }
      changed = true;
    }

    if (changed) fs.writeFileSync(frHppPath, frHpp);
  }

  const frCppPath = path.join(cppDirAbs, "fr.cpp");
  if (fs.existsSync(frCppPath)) {
    let frCpp = fs.readFileSync(frCppPath, "utf8");
    const looksLikeNoAsmGmpBackend = frCpp.includes("mpn_add_n") || frCpp.includes("mpn_mul_1");
    if (looksLikeNoAsmGmpBackend && frCpp.includes("uint64_t")) {
      frCpp = frCpp.replace(/\buint64_t\b/g, "mp_limb_t");
      fs.writeFileSync(frCppPath, frCpp);
    }
  }
}

function shellQuote(s) {
  const t = String(s);
  if (/^[A-Za-z0-9_./-]+$/.test(t)) return t;
  return JSON.stringify(t);
}

function assertNonEmptyArtifact(zk, filePath, label) {
  const abs = zk.resolvePath(filePath);
  if (!fs.existsSync(abs)) {
    throw new Error(`Missing ${label} at ${abs} after Groth16 setup.`);
  }
  const size = fs.statSync(abs).size;
  if (!Number.isFinite(size) || size <= 0) {
    throw new Error(`Empty ${label} at ${abs} after Groth16 setup.`);
  }
}

function ensureGroth16ZkeyAndVkey(
  zk,
  { circomFile, r1csFile, symFile, ptauFile, zkeyFile, vkeyFile, outDir = ".", circomBin }
) {
  ensureCircuitCompiled(zk, { circomFile, r1csFile, symFile, outDir, circomBin });

  const zkeyAbs = zk.resolvePath(zkeyFile);
  const vkeyAbs = zk.resolvePath(vkeyFile);
  const r1csAbs = zk.resolvePath(r1csFile);
  const zkeyOk = fs.existsSync(zkeyAbs);
  const vkeyOk = fs.existsSync(vkeyAbs);
  const sn = snarkjsCliToken();

  if (zkeyOk && vkeyOk) {
    try {
      const zSize = fs.statSync(zkeyAbs).size;
      const vSize = fs.statSync(vkeyAbs).size;
      if (zSize === 0 || vSize === 0) throw new Error("empty zkey/vkey");
      const r1csM = fs.statSync(r1csAbs).mtimeMs;
      const zkeyM = fs.statSync(zkeyAbs).mtimeMs;
      const vkeyM = fs.statSync(vkeyAbs).mtimeMs;
      if (zkeyM >= r1csM && vkeyM >= r1csM) {
        setupProgress("  [setup] Using cached zkey/vkey (skipped snarkjs setup).");
        return;
      }
    } catch {
      // fall through
    }
  }

  if (zkeyOk && !vkeyOk) {
    try {
      const zSize = fs.statSync(zkeyAbs).size;
      if (zSize > 0) {
        const r1csM = fs.statSync(r1csAbs).mtimeMs;
        const zkeyM = fs.statSync(zkeyAbs).mtimeMs;
        if (zkeyM >= r1csM) {
          setupProgress("  [setup] Exporting vkey from cached zkey...");
          const exp = zk.exec(`${sn} zkey export verificationkey ${zkeyFile} ${vkeyFile}`);
          if (!exp.ok) throw new Error(exp.stderr || exp.stdout);
          assertNonEmptyArtifact(zk, vkeyFile, "verification key");
          return;
        }
      }
    } catch (e) {
      if (String(e.message || e).includes("verification key")) throw e;
      // fall through to full setup
    }
  }

  zk.section("Setup (Generating Groth16 zkey/vkey)");
  setupProgress("  [setup] Generating Groth16 zkey (snarkjs groth16 setup — may take a few minutes)...");
  if (!fs.existsSync(zk.resolvePath(ptauFile))) {
    throw new Error(`Missing ptau file ${ptauFile}. Expected it to exist already.`);
  }

  const setup = zk.exec(`${sn} groth16 setup ${r1csFile} ${ptauFile} ${zkeyFile}`);
  if (!setup.ok) throw new Error(setup.stderr || setup.stdout || "snarkjs groth16 setup failed");
  assertNonEmptyArtifact(zk, zkeyFile, "proving key (zkey)");

  setupProgress("  [setup] Exporting verification key...");
  const exp = zk.exec(`${sn} zkey export verificationkey ${zkeyFile} ${vkeyFile}`);
  if (!exp.ok) throw new Error(exp.stderr || exp.stdout || "snarkjs vkey export failed");
  assertNonEmptyArtifact(zk, vkeyFile, "verification key");
}

function prepareGroth16(
  zk,
  {
    rapidsnarkBin,
    circomFile,
    r1csFile,
    ptauFile,
    zkeyFile,
    vkeyFile,
    outDir = ".",
    circomBin,
  }
) {
  if (rapidsnarkBin) ensureRapidsnarkAvailable(zk, rapidsnarkBin);

  ensureGroth16ZkeyAndVkey(zk, {
    circomFile,
    r1csFile,
    ptauFile,
    zkeyFile,
    vkeyFile,
    outDir,
    circomBin,
  });

  const witness = ensureCppWitnessGenerator(zk, {
    circomFile,
    outDir,
    circomBin,
  });

  assertNonEmptyArtifact(zk, zkeyFile, "proving key (zkey)");
  assertNonEmptyArtifact(zk, vkeyFile, "verification key");
  assertNonEmptyArtifact(zk, witness.witnessBin, "C++ witness binary");

  return { ...witness, vkeyFile, zkeyFile, r1csFile };
}

module.exports = {
  createZkUtils,
  prepareGroth16,
  shellQuote,
};

