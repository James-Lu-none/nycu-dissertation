#!/usr/bin/env bash
# Build script for binutils-2.29 (Targets: nm, readelf)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

CONFIG_OPTIONS="--disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld --disable-werror"
export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm in isolated build dir
BUILD_TMP_BC=$(mktemp -d /tmp/binutils229_bc_XXXXXX)
cd "${BUILD_TMP_BC}"
cp -r "${SRC_DIR}/." .
./configure CC=wllvm CFLAGS="-g -O1" ${CONFIG_OPTIONS}
make -j"$(nproc)" all-binutils

mkdir -p "${BUILD_TMP_BC}/bc_bins"
extract-bc binutils/nm-new
cp binutils/nm-new.bc "${BUILD_TMP_BC}/bc_bins/nm.bc"
cp binutils/nm-new "${BUILD_TMP_BC}/bc_bins/nm_base"

extract-bc binutils/readelf
cp binutils/readelf.bc "${BUILD_TMP_BC}/bc_bins/readelf.bc"
cp binutils/readelf "${BUILD_TMP_BC}/bc_bins/readelf_base"

# Export nm
NM_OUT="${OUT_DIR}/nm"
mkdir -p "${NM_OUT}"
cp "${BUILD_TMP_BC}/bc_bins/nm.bc" "${NM_OUT}/nm.bc"
cp "${BUILD_TMP_BC}/bc_bins/nm_base" "${NM_OUT}/nm_base"
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${NM_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${NM_OUT}/nm.bc"

# Export readelf
READELF_OUT="${OUT_DIR}/readelf"
mkdir -p "${READELF_OUT}"
cp "${BUILD_TMP_BC}/bc_bins/readelf.bc" "${READELF_OUT}/readelf.bc"
cp "${BUILD_TMP_BC}/bc_bins/readelf_base" "${READELF_OUT}/readelf_base"
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${READELF_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${READELF_OUT}/readelf.bc"
rm -rf "${BUILD_TMP_BC}"

# 2. Compile instrumented binaries in fresh build dir
BUILD_TMP_INST=$(mktemp -d /tmp/binutils229_inst_XXXXXX)
cd "${BUILD_TMP_INST}"
cp -r "${SRC_DIR}/." .
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie" \
    LDFLAGS="-fsanitize=address -no-pie -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive" \
    ${CONFIG_OPTIONS}
make -j"$(nproc)" all-binutils

cp "binutils/nm-new" "${NM_OUT}/nm_inst"
cp "binutils/readelf" "${READELF_OUT}/readelf_inst"
rm -rf "${BUILD_TMP_INST}"

echo "[BUILD][binutils-2.29] Finished targets in ${OUT_DIR}"
