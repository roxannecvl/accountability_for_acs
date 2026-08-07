#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PTAU_DIR="${ROOT_DIR}/powersOfTau"
PTAU_FILE="${PTAU_DIR}/powersOfTau28_hez_final_19.ptau"

mkdir -p "${PTAU_DIR}"

if [[ -f "${PTAU_FILE}" ]]; then
  echo "ptau already present at ${PTAU_FILE}"
  exit 0
fi

# Hermez/Polygon zkEVM maintained PoT file mirror.
URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_19.ptau"

echo "Downloading ptau..."
echo "  ${URL}"
curl -L --fail -o "${PTAU_FILE}.tmp" "${URL}"
mv "${PTAU_FILE}.tmp" "${PTAU_FILE}"
echo "Saved ${PTAU_FILE}"

