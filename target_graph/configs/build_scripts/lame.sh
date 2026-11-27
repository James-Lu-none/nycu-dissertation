#!/usr/bin/env bash
# Build script for lame-3.99.5 (Target: lame)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/lame"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/lame_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

# 1. Compile bitcode using wllvm
export LLVM_COMPILER=clang
./configure CC=wllvm CFLAGS="-g -O1" --disable-shared --disable-decoder
make -j"$(nproc)"
extract-bc frontend/lame
cp frontend/lame.bc "${TARGET_OUT}/lame.bc"
cp frontend/lame "${TARGET_OUT}/lame_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/lame.bc" "${TARGET_OUT}/lame.bc"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/lame_trace.bc" "${TARGET_OUT}/lame.bc"
clang -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/lame_trace.bc" \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -lncurses -ltinfo -lm -o "${TARGET_OUT}/lame_inst"

echo "[BUILD][lame] Finished building lame in ${TARGET_OUT}"
