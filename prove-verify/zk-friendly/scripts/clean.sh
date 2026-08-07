#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Drop heavy run outputs inside an artifacts dir, keep summary_*.json.
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
    # communication-costs also writes cft_only.json / revocation.json — drop those too
    if [[ "$base" == cft_only.json || "$base" == revocation.json ]]; then
      rm -f "$entry"
      continue
    fi
    rm -rf "$entry"
  done
  shopt -u nullglob

  # Remove the dir if nothing remains (e.g. after clean:results).
  if [[ -d "$dir" ]] && [[ -z "$(ls -A "$dir" 2>/dev/null || true)" ]]; then
    rmdir "$dir"
  fi
}

ALL=0
if [[ "${1:-}" == "--all" ]]; then
  ALL=1
elif [[ "${1:-}" != "" ]]; then
  echo "Usage: $0 [--all]" >&2
  exit 2
fi

ARTIFACT_DIRS=(
  "$ROOT_DIR/prove-verify/artifacts_bench_prove_verify"
  "$ROOT_DIR/prove-verify-no-cft/artifacts_bench_prove_verify_no_cft"
  "$ROOT_DIR/prove-verify-revocation/artifacts_bench_prove_verify_revocation"
  "$ROOT_DIR/merkle-vs-flat/artifacts_bench_merkle_vs_flat"
  "$ROOT_DIR/communication-costs/artifacts_measure_communication_size"
)

if [[ "$ALL" -eq 1 ]]; then
  # Nuclear: drop artifact folders entirely (summaries too) + node_modules.
  rm -rf "${ARTIFACT_DIRS[@]}" "$ROOT_DIR/node_modules"
else
  for d in "${ARTIFACT_DIRS[@]}"; do
    clean_artifacts_keep_summaries "$d"
  done
fi

# Circom / snarkjs build outputs (including a stray root-level generated/ if present).
rm -rf \
  "$ROOT_DIR/generated" \
  "$ROOT_DIR/prove-verify/generated" \
  "$ROOT_DIR/prove-verify-no-cft/generated" \
  "$ROOT_DIR/prove-verify-revocation/generated" \
  "$ROOT_DIR/merkle-vs-flat/generated"

# Generated circuits for the merkle-vs-flat sweep (keeps only the JS benchmark source).
rm -f "$ROOT_DIR/merkle-vs-flat"/flat_t*_u*.circom \
      "$ROOT_DIR/merkle-vs-flat"/merkle_t*_u*.circom 2>/dev/null || true

if [[ "$ALL" -eq 1 ]]; then
  echo "Cleaned artifact folders, generated outputs, and node_modules."
else
  echo "Cleaned generated artifacts (kept summary_*.json when present)."
fi
