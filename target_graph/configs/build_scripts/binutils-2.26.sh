#!/usr/bin/env bash
# Build script for binutils-2.26 (Target: cxxfilt)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/cxxfilt"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/binutils226_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

CONFIG_OPTIONS="--disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld"
export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm
./configure CC=wllvm CFLAGS="-g -O1" ${CONFIG_OPTIONS}
make -j"$(nproc)"
extract-bc binutils/cxxfilt
cp binutils/cxxfilt.bc "${TARGET_OUT}/cxxfilt.bc"
cp binutils/cxxfilt "${TARGET_OUT}/cxxfilt_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/cxxfilt.bc"

# 3. Compile instrumented binary with ASan and trace
make clean || true
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie" \
    LDFLAGS="-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive" \
    ${CONFIG_OPTIONS}
make -j"$(nproc)"
cp binutils/cxxfilt "${TARGET_OUT}/cxxfilt_inst"

echo "[BUILD][binutils-2.26] Finished building cxxfilt in ${TARGET_OUT}"
