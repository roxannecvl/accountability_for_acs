#!/usr/bin/env bash
# Delete ALL local benchmark / measure summaries under standard/.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "This will DELETE ALL local benchmark / measure summaries under standard/."
echo "It will NOT remove longfellow-zk/clang-build-release (use npm run clean:all)."
echo ""

read -r -p "Type 'delete' to confirm: " CONFIRM
if [[ "$CONFIRM" != "delete" ]]; then
  echo "Aborted."
  exit 1
fi

rm -rf \
  "$ROOT_DIR/prove-verify/artifacts_bench_prove_verify" \
  "$ROOT_DIR/prove-verify-no-cft/artifacts_bench_prove_verify_no_cft" \
  "$ROOT_DIR/prove-verify-revocation/artifacts_bench_prove_verify_revocation" \
  "$ROOT_DIR/merkle-vs-flat/artifacts_bench_merkle_vs_flat" \
  "$ROOT_DIR/communication-costs/artifacts_measure_communication_size"

echo "Deleted benchmark summaries and artifact folders."
