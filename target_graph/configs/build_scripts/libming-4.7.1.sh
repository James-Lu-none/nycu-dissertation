#!/usr/bin/env bash
# Build script for libming-4.7.1 (Target: swftophp)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/swftophp"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/libming471_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

# Ensure ming.h exists
if [[ ! -f src/ming.h && -f src/ming.h.in ]]; then
    sed -e 's/@MAJOR_VERSION@/0/' -e 's/@MINOR_VERSION@/4/' -e 's/@MICRO_VERSION@/7/' src/ming.h.in > src/ming.h
fi

# Ensure ming_config.h exists
if [[ ! -f src/ming_config.h ]]; then
    cat << 'EOF' > src/ming_config.h
#ifndef __MING_CONFIG_H
#define __MING_CONFIG_H
#define HAVE_DLFCN_H 1
#define HAVE_GETOPT 1
#define HAVE_GETOPT_H 1
#define HAVE_GETOPT_LONG 1
#define HAVE_INTTYPES_H 1
#define HAVE_MKSTEMP 1
#define HAVE_STDINT_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define STDC_HEADERS 1
#endif
EOF
fi

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

echo "[BUILD][libming-4.7.1] Finished building swftophp in ${TARGET_OUT}"
