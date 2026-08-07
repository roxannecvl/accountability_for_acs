#!/usr/bin/env node
"use strict";

/**
 * Thin entry for the MP-SPDZ sweep (same as `bash mpc/run_sweep.sh`).
 * Requires MP_SPDZ_PATH.
 */
const { spawnSync } = require("child_process");
const path = require("path");

const r = spawnSync("bash", [path.join(__dirname, "run_sweep.sh")], {
  stdio: "inherit",
  env: process.env,
});
process.exit(r.status ?? 1);
