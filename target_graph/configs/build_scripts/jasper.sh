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
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/imginfo.bc" "${TARGET_OUT}/imginfo.bc"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/imginfo_trace.bc" "${TARGET_OUT}/imginfo.bc"
clang -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/imginfo_trace.bc" -lm \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -o "${TARGET_OUT}/imginfo_inst"

echo "[BUILD][jasper] Finished building imginfo in ${TARGET_OUT}"
