#!/usr/bin/env node
"use strict";

const { runExperiment } = require("../lib/run_experiment");

runExperiment("link-decrypt").catch((err) => {
  console.error(err);
  process.exit(1);
});
