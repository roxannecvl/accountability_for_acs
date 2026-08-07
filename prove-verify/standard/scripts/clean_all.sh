#!/usr/bin/env bash
# Delete local summaries + the cmake build tree.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "This will DELETE:"
echo "  - all local benchmark / measure artifact folders under standard/"
echo "  - longfellow-zk/clang-build-release (rebuild required afterward)"
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
  "$ROOT_DIR/communication-costs/artifacts_measure_communication_size" \
  "$ROOT_DIR/longfellow-zk/clang-build-release"

echo "Deleted artifact folders and clang-build-release."
