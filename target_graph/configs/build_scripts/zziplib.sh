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

export LLVM_COMPILER=clang

# 1. Compile bitcode using wllvm
./configure CC="wllvm -g -O1 -D_USE_MMAP" CFLAGS="-g -O1 -D_USE_MMAP" --disable-shared
BUILD_SUBDIR="$(ls -d Linux_*.d 2>/dev/null | head -n 1 || echo "")"
if [[ -n "${BUILD_SUBDIR}" && -d "${BUILD_SUBDIR}" ]]; then
    make -j"$(nproc)" -C "${BUILD_SUBDIR}/zzip"
    make -j"$(nproc)" -C "${BUILD_SUBDIR}/bins"
    extract-bc "${BUILD_SUBDIR}/bins/unzzipcat-mem"
    cp "${BUILD_SUBDIR}/bins/unzzipcat-mem.bc" "${TARGET_OUT}/unzzipcat-mem.bc"
    cp "${BUILD_SUBDIR}/bins/unzzipcat-mem" "${TARGET_OUT}/unzzipcat-mem_base"
else
    make -j"$(nproc)" -C zzip
    make -j"$(nproc)" -C bins
    extract-bc bins/unzzipcat-mem
    cp bins/unzzipcat-mem.bc "${TARGET_OUT}/unzzipcat-mem.bc"
    cp bins/unzzipcat-mem "${TARGET_OUT}/unzzipcat-mem_base"
fi

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/unzzipcat-mem.bc" "${TARGET_OUT}/unzzipcat-mem.bc"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/unzzipcat-mem_trace.bc" "${TARGET_OUT}/unzzipcat-mem.bc"
clang -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/unzzipcat-mem_trace.bc" \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -lm -lz -o "${TARGET_OUT}/unzzipcat-mem_inst"

echo "[BUILD][zziplib] Finished building unzzipcat-mem in ${TARGET_OUT}"
