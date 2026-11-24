#!/usr/bin/env bash
# Build script for binutils-2.29 (Targets: nm, readelf)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

BUILD_TMP=$(mktemp -d /tmp/binutils229_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

CONFIG_OPTIONS="--disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld"
export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm
./configure CC=wllvm CFLAGS="-g -O1" ${CONFIG_OPTIONS}
make -j"$(nproc)"

mkdir -p "${BUILD_TMP}/bc_bins"
extract-bc binutils/nm-new
cp binutils/nm-new.bc "${BUILD_TMP}/bc_bins/nm.bc"
cp binutils/nm-new "${BUILD_TMP}/bc_bins/nm_base"

extract-bc binutils/readelf
cp binutils/readelf.bc "${BUILD_TMP}/bc_bins/readelf.bc"
cp binutils/readelf "${BUILD_TMP}/bc_bins/readelf_base"

# 2. Compile instrumented binaries with ASan and trace
make clean || true
./configure CC=clang \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie" \
    LDFLAGS="-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive" \
    ${CONFIG_OPTIONS}
make -j"$(nproc)"

# Export nm
NM_OUT="${OUT_DIR}/nm"
mkdir -p "${NM_OUT}"
cp "${BUILD_TMP}/bc_bins/nm.bc" "${NM_OUT}/nm.bc"
cp "${BUILD_TMP}/bc_bins/nm_base" "${NM_OUT}/nm_base"
cp "binutils/nm-new" "${NM_OUT}/nm_inst"

export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${NM_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${NM_OUT}/nm.bc"
echo "[BUILD][binutils-2.29] Finished target nm in ${NM_OUT}"

# Export readelf
READELF_OUT="${OUT_DIR}/readelf"
mkdir -p "${READELF_OUT}"
cp "${BUILD_TMP}/bc_bins/readelf.bc" "${READELF_OUT}/readelf.bc"
cp "${BUILD_TMP}/bc_bins/readelf_base" "${READELF_OUT}/readelf_base"
cp "binutils/readelf" "${READELF_OUT}/readelf_inst"

export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${READELF_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${READELF_OUT}/readelf.bc"
echo "[BUILD][binutils-2.29] Finished target readelf in ${READELF_OUT}"
