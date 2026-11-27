#!/usr/bin/env bash
# Build script for libtiff-4.0.6 (Targets: tiffcp, tiffcrop, tiffsplit)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

BUILD_TMP=$(mktemp -d /tmp/libtiff_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

export LLVM_COMPILER=clang

# 1. Build bitcode using wllvm
mkdir -p build_wllvm && cd build_wllvm
cmake .. -DCMAKE_C_COMPILER=wllvm -DCMAKE_C_FLAGS="-g -O1" -DBUILD_SHARED_LIBS=OFF
make -j"$(nproc)" tiffcp tiffcrop tiffsplit

# 2. Build instrumented binaries with ASan + trace
cd "${BUILD_TMP}"
# Export artifacts for each target
for tgt in tiffcp tiffcrop tiffsplit; do
    TARGET_OUT="${OUT_DIR}/${tgt}"
    mkdir -p "${TARGET_OUT}"
    
    extract-bc "${BUILD_TMP}/build_wllvm/tools/${tgt}"
    cp "${BUILD_TMP}/build_wllvm/tools/${tgt}.bc" "${TARGET_OUT}/${tgt}.bc"
    cp "${BUILD_TMP}/build_wllvm/tools/${tgt}" "${TARGET_OUT}/${tgt}_base"
    
    export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
    export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
    opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/${tgt}.bc"
    opt -load-pass-plugin=/usr/local/lib/TraceInstrumentPass.so -passes="target-graph-trace" -o "${TARGET_OUT}/${tgt}_trace.bc" "${TARGET_OUT}/${tgt}.bc"
    clang -g -O1 -fsanitize=address -no-pie \
        "${TARGET_OUT}/${tgt}_trace.bc" \
        -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
        -lm -lz -o "${TARGET_OUT}/${tgt}_inst"
    echo "[BUILD][libtiff] Finished target ${tgt} in ${TARGET_OUT}"
done
