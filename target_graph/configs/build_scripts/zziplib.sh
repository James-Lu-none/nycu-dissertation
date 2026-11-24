#!/usr/bin/env bash
# Build script for zziplib-0.13.62 (Target: unzzipcat-mem)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/unzzipcat-mem"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/zziplib_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

# 1. Compile bitcode using wllvm
export LLVM_COMPILER=clang
./configure CC=wllvm CFLAGS="-g -O1 -D_USE_MMAP" --disable-shared
make -j"$(nproc)"
extract-bc bins/unzzipcat-mem
cp bins/unzzipcat-mem.bc "${TARGET_OUT}/unzzipcat-mem.bc"
cp bins/unzzipcat-mem "${TARGET_OUT}/unzzipcat-mem_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/unzzipcat-mem.bc"

# 3. Compile instrumented binary with ASan and trace
make clean || true
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie -D_USE_MMAP" \
    LDFLAGS="-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive" \
    --disable-shared
make -j"$(nproc)"
cp bins/unzzipcat-mem "${TARGET_OUT}/unzzipcat-mem_inst"

echo "[BUILD][zziplib] Finished building unzzipcat-mem in ${TARGET_OUT}"
