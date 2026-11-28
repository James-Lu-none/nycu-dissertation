#!/usr/bin/env bash
# Build script for jhead-3.04 (Target: jhead)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/jhead"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/jhead_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp "${SRC_DIR}"/*.c "${SRC_DIR}"/*.h . 2>/dev/null || true

SRCS="jhead.c jpgfile.c jpgqguess.c paths.c exif.c iptc.c gpsinfo.c makernote.c"

# 1. Compile bitcode
clang -g -O1 -emit-llvm -c ${SRCS}
llvm-link -o "${TARGET_OUT}/jhead.bc" *.bc

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/jhead.bc" "${TARGET_OUT}/jhead.bc"

# 3. Compile base binary
clang -g -O1 -no-pie ${SRCS} -o "${TARGET_OUT}/jhead_base" -lm

# 4. Instrument bitcode with TraceInstrumentPass and compile ASan binary
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/jhead_trace.bc" "${TARGET_OUT}/jhead.bc"
clang -g -O1 -no-pie -fsanitize=address \
    "${TARGET_OUT}/jhead_trace.bc" \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -o "${TARGET_OUT}/jhead_inst" -lm

echo "[BUILD][jhead] Finished building jhead in ${TARGET_OUT}"
