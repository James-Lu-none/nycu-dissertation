#!/usr/bin/env bash
# Build script for binutils-2.26 (Target: cxxfilt)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/cxxfilt"
mkdir -p "${TARGET_OUT}"
CONFIG_OPTIONS="--disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld --disable-werror"
export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm in isolated build dir
BUILD_TMP_BC=$(mktemp -d /tmp/binutils226_bc_XXXXXX)
cd "${BUILD_TMP_BC}"
cp -r "${SRC_DIR}/." .
./configure CC=wllvm CFLAGS="-g -O1" ${CONFIG_OPTIONS}
make -j"$(nproc)" all-binutils
extract-bc binutils/cxxfilt
cp binutils/cxxfilt.bc "${TARGET_OUT}/cxxfilt.bc"
cp binutils/cxxfilt "${TARGET_OUT}/cxxfilt_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/cxxfilt.bc" "${TARGET_OUT}/cxxfilt.bc"
rm -rf "${BUILD_TMP_BC}"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/cxxfilt_trace.bc" "${TARGET_OUT}/cxxfilt.bc"
clang -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/cxxfilt_trace.bc" \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -ldl -lm -o "${TARGET_OUT}/cxxfilt_inst"

echo "[BUILD][binutils-2.26] Finished building cxxfilt in ${TARGET_OUT}"
