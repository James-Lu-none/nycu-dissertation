#!/usr/bin/env bash
# Build script for libxml2-2.9.4 (Target: xmllint)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/xmllint"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/libxml2_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm
if [[ -f autogen.sh ]]; then
    ./autogen.sh --disable-shared CC=wllvm CFLAGS="-g -O1"
elif [[ -f configure ]]; then
    ./configure --disable-shared CC=wllvm CFLAGS="-g -O1"
fi
make -j"$(nproc)" xmllint
extract-bc xmllint
cp xmllint.bc "${TARGET_OUT}/xmllint.bc"
cp xmllint "${TARGET_OUT}/xmllint_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/xmllint.bc" "${TARGET_OUT}/xmllint.bc"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/xmllint_trace.bc" "${TARGET_OUT}/xmllint.bc"
clang -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/xmllint_trace.bc" \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -lm -lz -ldl -o "${TARGET_OUT}/xmllint_inst"

echo "[BUILD][libxml2] Finished building xmllint in ${TARGET_OUT}"
