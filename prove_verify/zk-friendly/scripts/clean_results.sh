#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "This will DELETE ALL benchmark summaries (summary_*.json, summary_latest.json)."
echo "It will NOT delete node_modules unless you run npm run clean:all."
echo ""

read -r -p "Type 'delete' to confirm: " CONFIRM
if [[ "$CONFIRM" != "delete" ]]; then
  echo "Aborted."
  exit 1
fi

rm -f \
  "$ROOT_DIR/merkle_vs_flat_bench/artifacts_bench_merkle_vs_flat"/summary_*.json \
  "$ROOT_DIR/merkle_vs_flat_bench/artifacts_bench_merkle_vs_flat"/summary_latest.json \
  "$ROOT_DIR/prove_verify/artifacts_bench_prove_verify"/summary_*.json \
  "$ROOT_DIR/prove_verify/artifacts_bench_prove_verify"/summary_latest.json \
  "$ROOT_DIR/prove_verify_no_cft/artifacts_bench_prove_verify_no_cft"/summary_*.json \
  "$ROOT_DIR/prove_verify_no_cft/artifacts_bench_prove_verify_no_cft"/summary_latest.json \
  2>/dev/null || true

echo "Deleted benchmark summaries."
