#!/usr/bin/env bash
# Build script for bento4-1.5.0 (Target: mp42aac)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/mp42aac"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/bento4_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

# 1. Compile bitcode using wllvm
export LLVM_COMPILER=clang
mkdir -p build_bc && cd build_bc
cmake .. \
    -DCMAKE_C_COMPILER=wllvm \
    -DCMAKE_CXX_COMPILER=wllvm++ \
    -DCMAKE_C_FLAGS="-g -O1" \
    -DCMAKE_CXX_FLAGS="-g -O1" \
    -DCMAKE_BUILD_TYPE=Debug
make -j"$(nproc)" mp42aac
extract-bc mp42aac
cp mp42aac.bc "${TARGET_OUT}/mp42aac.bc"
cp mp42aac "${TARGET_OUT}/mp42aac_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/mp42aac.bc" "${TARGET_OUT}/mp42aac.bc"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/mp42aac_trace.bc" "${TARGET_OUT}/mp42aac.bc"
clang++ -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/mp42aac_trace.bc" \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -lm -o "${TARGET_OUT}/mp42aac_inst"

echo "[BUILD][bento4] Finished building mp42aac in ${TARGET_OUT}"
