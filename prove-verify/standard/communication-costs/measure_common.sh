#!/usr/bin/env bash
# Shared helpers for Longfellow proof-size measure scripts.
# Sourced by build_measure_longfellow_*.sh (expects SCRIPT_DIR already set).

STANDARD_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Local checkout: standard/longfellow-zk/{lib,clang-build-release}
# Docker image:  /bench/{lib,clang-build-release}  (LONGFELLOW_BUILD_DIR may be set)
if [[ -n "${LONGFELLOW_BUILD_DIR:-}" && -d "${LONGFELLOW_BUILD_DIR}" ]]; then
  BLD="${LONGFELLOW_BUILD_DIR}"
elif [[ -d "${STANDARD_ROOT}/longfellow-zk/clang-build-release" ]]; then
  BLD="${STANDARD_ROOT}/longfellow-zk/clang-build-release"
else
  BLD="${STANDARD_ROOT}/clang-build-release"
fi

if [[ -f "${STANDARD_ROOT}/longfellow-zk/lib/CMakeLists.txt" ]]; then
  LIB="${STANDARD_ROOT}/longfellow-zk/lib"
  LF_ROOT="${STANDARD_ROOT}/longfellow-zk"
elif [[ -f "${STANDARD_ROOT}/lib/CMakeLists.txt" ]]; then
  LIB="${STANDARD_ROOT}/lib"
  LF_ROOT="${STANDARD_ROOT}"
else
  LIB="${STANDARD_ROOT}/longfellow-zk/lib"
  LF_ROOT="${STANDARD_ROOT}/longfellow-zk"
fi

CXX_BIN="${CXX:-c++}"

# OpenSSL / zstd: Homebrew on macOS; system paths on Debian/Ubuntu (Docker).
OPENSSL_INC="${OPENSSL_INC:-}"
LINK_LIB_DIRS=()
if [[ -z "${OPENSSL_INC}" ]]; then
  if [[ -d /opt/homebrew/include/openssl ]]; then
    OPENSSL_INC="-I/opt/homebrew/include"
    LINK_LIB_DIRS+=("-L/opt/homebrew/lib")
  elif [[ -d /usr/local/opt/openssl@3/include ]]; then
    OPENSSL_INC="-I/usr/local/opt/openssl@3/include"
    LINK_LIB_DIRS+=("-L/usr/local/opt/openssl@3/lib")
  fi
fi
