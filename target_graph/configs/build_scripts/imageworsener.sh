#!/usr/bin/env bash
# Build script for imageworsener-1.3.1 (Target: imagew)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/imagew"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/imagew_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

# 1. Compile bitcode using wllvm
export LLVM_COMPILER=clang
./configure CC=wllvm CFLAGS="-g -O1" --disable-shared
make -j"$(nproc)"
extract-bc src/imagew
cp src/imagew.bc "${TARGET_OUT}/imagew.bc"
cp src/imagew "${TARGET_OUT}/imagew_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/imagew.bc"

# 3. Compile instrumented binary with ASan and trace
make clean || true
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie" \
    LDFLAGS="-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive" \
    --disable-shared
make -j"$(nproc)"
cp src/imagew "${TARGET_OUT}/imagew_inst"

echo "[BUILD][imageworsener] Finished building imagew in ${TARGET_OUT}"
