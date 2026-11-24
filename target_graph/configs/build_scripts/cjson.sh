#!/usr/bin/env bash
# Build script for cJSON-1.7.8 (Target: cjson_test)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/cjson_test"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/cjson_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp "${SRC_DIR}/cJSON.c" "${SRC_DIR}/cJSON.h" .

# Test harness covering both get_object_item and cJSON_Minify
cat << 'EOF' > cjson_test.c
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = (char *)malloc(sz + 1);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, sz, f);
    data[sz] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(data);
    if (json) {
        cJSON_GetObjectItemCaseSensitive(json, "key");
        cJSON_Delete(json);
    }
    cJSON_Minify(data);
    free(data);
    return 0;
}
EOF

# 1. Compile bitcode
clang -g -O1 -emit-llvm -c cJSON.c -o cJSON.bc
clang -g -O1 -emit-llvm -c cjson_test.c -o cjson_test.bc
llvm-link -o "${TARGET_OUT}/cjson_test.bc" cJSON.bc cjson_test.bc

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${TARGET_OUT}/cjson_test.bc"

# 3. Compile base binary
clang -g -O1 -no-pie cJSON.c cjson_test.c -o "${TARGET_OUT}/cjson_test_base" -lm

# 4. Compile instrumented binary for ASan crash trace
clang -g -O1 -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,no-prune \
    cJSON.c cjson_test.c \
    -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
    -o "${TARGET_OUT}/cjson_test_inst" -lm

echo "[BUILD][cJSON] Finished building cjson_test in ${TARGET_OUT}"
