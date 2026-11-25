#!/usr/bin/env bash
# Build script for jasper-1.900.1 (Target: imginfo)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/imginfo"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/jasper_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

# 1. Compile bitcode using wllvm
export LLVM_COMPILER=clang
./configure CC=wllvm CFLAGS="-g -O1" --disable-shared
make -j"$(nproc)"
extract-bc src/appl/imginfo
cp src/appl/imginfo.bc "${TARGET_OUT}/imginfo.bc"
cp src/appl/imginfo "${TARGET_OUT}/imginfo_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/imginfo.bc"

# 3. Compile instrumented binary with ASan and trace
make clean || true
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie" \
    --disable-shared
make -j"$(nproc)" -C src/libjasper
make -j"$(nproc)" -C src/appl imginfo.o
clang -g -O1 -fsanitize=address -no-pie \
    src/appl/imginfo.o src/libjasper/.libs/libjasper.a -lm \
    -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
    -o "${TARGET_OUT}/imginfo_inst"

echo "[BUILD][jasper] Finished building imginfo in ${TARGET_OUT}"
