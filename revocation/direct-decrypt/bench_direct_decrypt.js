#!/usr/bin/env node
"use strict";

const { runExperiment } = require("../lib/run_experiment");

runExperiment("direct-decrypt").catch((err) => {
  console.error(err);
  process.exit(1);
});
