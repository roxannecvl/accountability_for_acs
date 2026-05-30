#!/usr/bin/env bash
#
# Sweep runner for the MPC revocation benchmark (requires MP-SPDZ).
#
# Parameters (env vars):
#   NUMS         space- or comma-separated CFT set sizes (default below)
#   ITERATIONS   runs per size (default: 10)
#   TAU          predicate threshold (default: 2)
#   OUTDIR       sweep output directory (default: sweep_<timestamp>)
#   MP_SPDZ_PATH path to MP-SPDZ install (passed through to pet_mpc.js)
#
# Output:
#   $OUTDIR/results.csv   raw rows from pet_mpc.js
#   $OUTDIR/run.stdout / run.log
#
# After a sweep, convert to plot-ready CSVs in ../results/:
#   python3 summarize.py "$OUTDIR/results.csv"
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BENCH="${BENCH:-./pet_mpc.js}"
NUMS_RAW="${NUMS:-10 20 50 100 200 500 1000}"
ITERATIONS="${ITERATIONS:-10}"
TAU="${TAU:-2}"
OUTDIR="${OUTDIR:-sweep_$(date +%Y%m%d_%H%M%S)}"

if [[ ! -f "$BENCH" ]]; then
  echo "ERROR: bench file not found: $BENCH" >&2
  exit 2
fi

NUMS_LIST=($(echo "$NUMS_RAW" | tr ',' ' '))
NUMS_SPACE_SEPARATED="${NUMS_LIST[*]}"

mkdir -p "$OUTDIR"
CSV="$OUTDIR/results.csv"
LOG="$OUTDIR/run.log"
STDOUT_LOG="$OUTDIR/run.stdout"
: > "$LOG"

export RESULTS_CSV="$CSV"
[[ -n "${MP_SPDZ_PATH:-}" ]] && export MP_SPDZ_PATH

total=$(( ${#NUMS_LIST[@]} * ITERATIONS ))
{
  echo "Output dir:    $OUTDIR"
  echo "Bench:         $BENCH"
  echo "NUMS:          ${NUMS_LIST[*]}"
  echo "ITERATIONS:    $ITERATIONS  (per N)"
  echo "TAU:           $TAU"
  echo "MP_SPDZ_PATH:  ${MP_SPDZ_PATH:-(default in JS)}"
  echo "CSV:           $CSV"
  echo "Total runs:    $total"
  echo
} | tee -a "$LOG"

start=$(date +%s)
echo "Launching node $BENCH ..." | tee -a "$LOG"

if CFT_BENCH_NUMS="$NUMS_SPACE_SEPARATED" \
   CFT_BENCH_ITERS="$ITERATIONS" \
   CFT_MIN_PID_COUNT="$TAU" \
   node "$BENCH" > "$STDOUT_LOG" 2>&1; then
  rc=0
  status="OK"
else
  rc=$?
  status="FAIL (exit ${rc})"
fi
dur=$(( $(date +%s) - start ))

{
  echo
  echo "──── ${status} in $((dur/60))m $((dur%60))s ────"
  echo "Full stdout: $STDOUT_LOG"
  echo "CSV:         $CSV"
  if [[ -f "$CSV" ]]; then
    rows=$(($(wc -l < "$CSV") - 1))
    echo "Rows:        $rows  (expected ${total})"
  fi
  echo
  echo "Next: python3 summarize.py \"$CSV\""
} | tee -a "$LOG"

exit "$rc"
