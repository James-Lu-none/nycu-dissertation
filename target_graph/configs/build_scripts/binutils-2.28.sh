#!/usr/bin/env bash
# Build script for binutils-2.28 (Targets: objdump, objcopy)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

BUILD_TMP=$(mktemp -d /tmp/binutils228_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

CONFIG_OPTIONS="--disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld"
export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm
./configure CC=wllvm CFLAGS="-g -O1" ${CONFIG_OPTIONS}
make -j"$(nproc)"

mkdir -p "${BUILD_TMP}/bc_bins"
extract-bc binutils/objdump
cp binutils/objdump.bc "${BUILD_TMP}/bc_bins/objdump.bc"
cp binutils/objdump "${BUILD_TMP}/bc_bins/objdump_base"

extract-bc binutils/objcopy
cp binutils/objcopy.bc "${BUILD_TMP}/bc_bins/objcopy.bc"
cp binutils/objcopy "${BUILD_TMP}/bc_bins/objcopy_base"

# 2. Compile instrumented binaries with ASan and trace
make clean || true
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie" \
    LDFLAGS="-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive" \
    ${CONFIG_OPTIONS}
make -j"$(nproc)"

for tgt in objdump objcopy; do
    TARGET_OUT="${OUT_DIR}/${tgt}"
    mkdir -p "${TARGET_OUT}"
    cp "${BUILD_TMP}/bc_bins/${tgt}.bc" "${TARGET_OUT}/${tgt}.bc"
    cp "${BUILD_TMP}/bc_bins/${tgt}_base" "${TARGET_OUT}/${tgt}_base"
    cp "binutils/${tgt}" "${TARGET_OUT}/${tgt}_inst"

    export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
    export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
    opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/${tgt}.bc"
    echo "[BUILD][binutils-2.28] Finished target ${tgt} in ${TARGET_OUT}"
done
