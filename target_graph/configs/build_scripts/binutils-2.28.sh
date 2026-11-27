#!/usr/bin/env bash
# Build script for binutils-2.28 (Targets: objdump, objcopy)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

CONFIG_OPTIONS="--disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld --disable-werror"
export LLVM_COMPILER=clang
export ASAN_OPTIONS="detect_leaks=0"

# 1. Compile bitcode using wllvm in isolated build dir
BUILD_TMP_BC=$(mktemp -d /tmp/binutils228_bc_XXXXXX)
cd "${BUILD_TMP_BC}"
cp -r "${SRC_DIR}/." .
./configure CC=wllvm CFLAGS="-g -O1" ${CONFIG_OPTIONS}
make -j"$(nproc)" all-binutils

mkdir -p "${BUILD_TMP_BC}/bc_bins"
extract-bc binutils/objdump
cp binutils/objdump.bc "${BUILD_TMP_BC}/bc_bins/objdump.bc"
cp binutils/objdump "${BUILD_TMP_BC}/bc_bins/objdump_base"

extract-bc binutils/objcopy
cp binutils/objcopy.bc "${BUILD_TMP_BC}/bc_bins/objcopy.bc"
cp binutils/objcopy "${BUILD_TMP_BC}/bc_bins/objcopy_base"

for tgt in objdump objcopy; do
    TARGET_OUT="${OUT_DIR}/${tgt}"
    mkdir -p "${TARGET_OUT}"
    cp "${BUILD_TMP_BC}/bc_bins/${tgt}.bc" "${TARGET_OUT}/${tgt}.bc"
    cp "${BUILD_TMP_BC}/bc_bins/${tgt}_base" "${TARGET_OUT}/${tgt}_base"

    export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
    export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
    opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/${tgt}.bc"
    opt -load-pass-plugin=/usr/local/lib/TraceInstrumentPass.so -passes="target-graph-trace" -o "${TARGET_OUT}/${tgt}_trace.bc" "${TARGET_OUT}/${tgt}.bc"
    clang -g -O1 -fsanitize=address -no-pie \
        "${TARGET_OUT}/${tgt}_trace.bc" \
        -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
        -ldl -lm -o "${TARGET_OUT}/${tgt}_inst"
    echo "[BUILD][binutils-2.28] Finished target ${tgt} in ${TARGET_OUT}"
done
rm -rf "${BUILD_TMP_BC}"
