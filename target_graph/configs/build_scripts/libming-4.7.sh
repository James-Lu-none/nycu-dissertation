#!/usr/bin/env bash
# Build script for libming-4.7 (Target: swftophp)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/swftophp"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/libming47_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

SRCS="util/outputscript.c util/main.c util/action.c util/blocktypes.c util/decompile.c util/parser.c util/read.c util/vasprintf.c"
if [[ -f src/blocks/error.c ]]; then
    SRCS="${SRCS} src/blocks/error.c"
elif [[ -f src/error.c ]]; then
    SRCS="${SRCS} src/error.c"
fi
INCS="-Isrc -Iutil -DSWFPHP"

# 1. Compile bitcode
clang -g -O1 ${INCS} -emit-llvm -c ${SRCS}
llvm-link -o "${TARGET_OUT}/swftophp.bc" *.bc

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/swftophp.bc"

# 3. Compile base binary
clang -g -O1 ${INCS} -no-pie ${SRCS} -o "${TARGET_OUT}/swftophp_base" -lm -lz

# 4. Compile instrumented binary
clang -g -O1 ${INCS} -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,no-prune \
    ${SRCS} \
    -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
    -o "${TARGET_OUT}/swftophp_inst" -lm -lz

echo "[BUILD][libming-4.7] Finished building swftophp in ${TARGET_OUT}"
