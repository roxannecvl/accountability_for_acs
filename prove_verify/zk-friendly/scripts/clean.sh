#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

clean_artifacts_keep_summaries() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    return 0
  fi

  shopt -s nullglob
  for entry in "$dir"/*; do
    local base
    base="$(basename "$entry")"
    if [[ "$base" == summary_*.json || "$base" == summary_latest.json ]]; then
      continue
    fi
    rm -rf "$entry"
  done
  shopt -u nullglob
}

ALL=0
if [[ "${1:-}" == "--all" ]]; then
  ALL=1
elif [[ "${1:-}" != "" ]]; then
  echo "Usage: $0 [--all]" >&2
  exit 2
fi

# Per-benchmark artifact dirs (kept summaries, dropped everything else).
clean_artifacts_keep_summaries "$ROOT_DIR/merkle_vs_flat_bench/artifacts_bench_merkle_vs_flat"
clean_artifacts_keep_summaries "$ROOT_DIR/prove_verify/artifacts_bench_prove_verify"
clean_artifacts_keep_summaries "$ROOT_DIR/prove_verify_no_cft/artifacts_bench_prove_verify_no_cft"

# Compiled circuit outputs (r1cs / wasm / zkey / vkey / witness binaries).
rm -rf \
  "$ROOT_DIR/merkle_vs_flat_bench/generated" \
  "$ROOT_DIR/prove_verify/generated" \
  "$ROOT_DIR/prove_verify_no_cft/generated"

# Generated circuits for the merkle-vs-flat sweep (keeps only the JS benchmark source).
rm -f "$ROOT_DIR/merkle_vs_flat_bench"/flat_t*_u*.circom \
      "$ROOT_DIR/merkle_vs_flat_bench"/merkle_t*_u*.circom 2>/dev/null || true

if [[ "$ALL" -eq 1 ]]; then
  rm -rf "$ROOT_DIR/node_modules"
fi

echo "Cleaned generated artifacts (kept summary_*.json)."
