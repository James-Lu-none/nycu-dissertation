#!/usr/bin/env bash
# Build, instrument, trace, and extract bitcode/graphs for 5 non-benchmark projects.
set -euo pipefail

ROOT_DIR="/workspace"
CASES_DIR="${ROOT_DIR}/cases"
BUILD_DIR="${ROOT_DIR}/build_test"
mkdir -p "${CASES_DIR}" "${BUILD_DIR}"

export LLVM_COMPILER=clang

echo "=========================================================="
echo " Building 5 Non-Benchmark Cases for Target-Conditioned PGL"
echo "=========================================================="

# -----------------------------------------------------------------------------
# CASE 1: lua-5.3.5_lua_CVE-2019-6706
# -----------------------------------------------------------------------------
echo "[1/5] Building lua-5.3.5_lua_CVE-2019-6706..."
CASE1_ID="lua-5.3.5_lua_CVE-2019-6706"
CASE1_DIR="${CASES_DIR}/${CASE1_ID}"
mkdir -p "${CASE1_DIR}"

# Write PoC
cat << "EOF" > "${CASE1_DIR}/poc.lua"
f = load(function() end); debug.upvaluejoin(f, 1, f, 1)
EOF

cd "${BUILD_DIR}"
if [[ ! -d "lua_src" ]]; then
    git clone --depth 1 -b v5.3.5 https://github.com/lua/lua.git lua_src
fi
cd lua_src

# Compile bitcode
clang -g -O1 -emit-llvm -c $(ls *.c | grep -v luac.c)
llvm-link -o "${CASE1_DIR}/lua.bc" $(ls *.bc | grep -v luac.bc)

# Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${CASE1_ID}"
export TARGET_GRAPH_OUT_DIR="${CASE1_DIR}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${CASE1_DIR}/lua.bc"

# Build base binary
clang -g -O1 -no-pie $(ls *.c | grep -v luac.c) -o "${CASE1_DIR}/lua_base" -lm -ldl

# Build instrumented binary
clang -g -O1 -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard \
    $(ls *.c | grep -v luac.c) \
    -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
    -o "${CASE1_DIR}/lua_inst" -lm -ldl

# Run PoC and capture trace
export TARGET_GRAPH_TRACE_FILE="${CASE1_DIR}/trace_crash.txt"
set +e
"${CASE1_DIR}/lua_inst" "${CASE1_DIR}/poc.lua" > /dev/null 2> "${CASE1_DIR}/crash_stderr.txt"
set -e
echo "Case 1 complete. Crash stderr lines: $(wc -l < "${CASE1_DIR}/crash_stderr.txt")"

# -----------------------------------------------------------------------------
# CASE 2: cJSON-1.7.8_cJSON_CVE-2019-1010239
# -----------------------------------------------------------------------------
echo "[2/5] Building cJSON-1.7.8_cJSON_CVE-2019-1010239..."
CASE2_ID="cJSON-1.7.8_cJSON_CVE-2019-1010239"
CASE2_DIR="${CASES_DIR}/${CASE2_ID}"
mkdir -p "${CASE2_DIR}"

# Write PoC
echo -n "[1, 2, 3]" > "${CASE2_DIR}/poc.json"

cd "${BUILD_DIR}"
if [[ ! -d "cjson_src" ]]; then
    git clone --depth 1 -b v1.7.8 https://github.com/DaveGamble/cJSON.git cjson_src
fi
cd cjson_src

# Driver harness
cat << "EOF" > cjson_test.c
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
    char *data = (char*)malloc(sz + 1);
    fread(data, 1, sz, f);
    data[sz] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(data);
    if (json) {
        cJSON_GetObjectItemCaseSensitive(json, "key");
        cJSON_Delete(json);
    }
    free(data);
    return 0;
}
EOF

# Compile bitcode
clang -g -O1 -emit-llvm -c cJSON.c -o cJSON.bc
clang -g -O1 -emit-llvm -c cjson_test.c -o cjson_test.bc
llvm-link -o "${CASE2_DIR}/cjson_test.bc" cJSON.bc cjson_test.bc

# Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${CASE2_ID}"
export TARGET_GRAPH_OUT_DIR="${CASE2_DIR}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${CASE2_DIR}/cjson_test.bc"

# Build base binary
clang -g -O1 cJSON.c cjson_test.c -o "${CASE2_DIR}/cjson_test_base" -lm

# Build instrumented binary
clang -g -O1 -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard \
    cJSON.c cjson_test.c \
    -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
    -o "${CASE2_DIR}/cjson_test_inst" -lm

# Run PoC and capture trace
export TARGET_GRAPH_TRACE_FILE="${CASE2_DIR}/trace_crash.txt"
set +e
"${CASE2_DIR}/cjson_test_inst" "${CASE2_DIR}/poc.json" > /dev/null 2> "${CASE2_DIR}/crash_stderr.txt"
set -e
echo "Case 2 complete. Crash stderr lines: $(wc -l < "${CASE2_DIR}/crash_stderr.txt")"

# -----------------------------------------------------------------------------
# CASE 3: jhead-3.04_jhead_issue54
# -----------------------------------------------------------------------------
echo "[3/5] Building jhead-3.04_jhead_issue54..."
CASE3_ID="jhead-3.04_jhead_issue54"
CASE3_DIR="${CASES_DIR}/${CASE3_ID}"
mkdir -p "${CASE3_DIR}"

# Write dummy jpeg
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xFF\xDB\x00\x43\x00\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00\xD2\xFF\xD9' > "${CASE3_DIR}/dummy.jpg"

cd "${BUILD_DIR}"
if [[ ! -d "jhead_src" ]]; then
    git clone https://github.com/Matthias-Wandel/jhead.git jhead_src
    cd jhead_src
    git checkout bf9a187~1
    cd ..
fi
cd jhead_src

# Compile bitcode
clang -g -O1 -emit-llvm -c jhead.c jpgfile.c jpgqguess.c paths.c exif.c iptc.c gpsinfo.c makernote.c
llvm-link -o "${CASE3_DIR}/jhead.bc" jhead.bc jpgfile.bc jpgqguess.bc paths.bc exif.bc iptc.bc gpsinfo.bc makernote.bc

# Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${CASE3_ID}"
export TARGET_GRAPH_OUT_DIR="${CASE3_DIR}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${CASE3_DIR}/jhead.bc"

# Build base binary
clang -g -O1 jhead.c jpgfile.c jpgqguess.c paths.c exif.c iptc.c gpsinfo.c makernote.c -o "${CASE3_DIR}/jhead_base" -lm

# Build instrumented binary
clang -g -O1 -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard \
    jhead.c jpgfile.c jpgqguess.c paths.c exif.c iptc.c gpsinfo.c makernote.c \
    -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
    -o "${CASE3_DIR}/jhead_inst" -lm

# Run PoC and capture trace
export TARGET_GRAPH_TRACE_FILE="${CASE3_DIR}/trace_crash.txt"
set +e
"${CASE3_DIR}/jhead_inst" -ds2020:01:01:1111111111111111111111111111111111111111 "${CASE3_DIR}/dummy.jpg" > /dev/null 2> "${CASE3_DIR}/crash_stderr.txt"
set -e
echo "Case 3 complete. Crash stderr lines: $(wc -l < "${CASE3_DIR}/crash_stderr.txt")"

# -----------------------------------------------------------------------------
# CASE 4: libtiff-4.0.6_tiffcrop_CVE-2016-10092
# -----------------------------------------------------------------------------
echo "[4/5] Building libtiff-4.0.6_tiffcrop_CVE-2016-10092..."
CASE4_ID="libtiff-4.0.6_tiffcrop_CVE-2016-10092"
CASE4_DIR="${CASES_DIR}/${CASE4_ID}"
mkdir -p "${CASE4_DIR}"

# Download PoC
curl -sL https://raw.githubusercontent.com/Hack-Me/Pocs_for_Multi_Versions/main/CVE-2016-10092/CVE-2016-10092_v4.0.6 -o "${CASE4_DIR}/poc.tif"

cd "${BUILD_DIR}"
if [[ ! -d "libtiff_src" ]]; then
    git clone --depth 1 -b v4.0.6 https://gitlab.com/libtiff/libtiff.git libtiff_src
fi
cd libtiff_src

# 1. Build bitcode using wllvm
rm -rf build_wllvm
mkdir -p build_wllvm && cd build_wllvm
cmake .. -DCMAKE_C_COMPILER=wllvm -DCMAKE_C_FLAGS="-g -O1" -DBUILD_SHARED_LIBS=OFF
make -j16 tiffcrop
extract-bc tools/tiffcrop
cp tools/tiffcrop.bc "${CASE4_DIR}/tiffcrop.bc"
cp tools/tiffcrop "${CASE4_DIR}/tiffcrop_base"

# Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${CASE4_ID}"
export TARGET_GRAPH_OUT_DIR="${CASE4_DIR}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${CASE4_DIR}/tiffcrop.bc"

# 2. Build instrumented binary
cd "${BUILD_DIR}/libtiff_src"
rm -rf build_inst
mkdir -p build_inst && cd build_inst
cmake .. \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive" \
    -DBUILD_SHARED_LIBS=OFF
make -j16 tiffcrop
cp tools/tiffcrop "${CASE4_DIR}/tiffcrop_inst"

# Run PoC and capture trace
export TARGET_GRAPH_TRACE_FILE="${CASE4_DIR}/trace_crash.txt"
set +e
"${CASE4_DIR}/tiffcrop_inst" -i "${CASE4_DIR}/poc.tif" /tmp/out.tif > /dev/null 2> "${CASE4_DIR}/crash_stderr.txt"
set -e
echo "Case 4 complete. Crash stderr lines: $(wc -l < "${CASE4_DIR}/crash_stderr.txt")"

# -----------------------------------------------------------------------------
# CASE 5: lame-3.99.5_lame_CVE-2015-9101
# -----------------------------------------------------------------------------
echo "[5/5] Building lame-3.99.5_lame_CVE-2015-9101..."
CASE5_ID="lame-3.99.5_lame_CVE-2015-9101"
CASE5_DIR="${CASES_DIR}/${CASE5_ID}"
mkdir -p "${CASE5_DIR}"

# Download PoC
curl -sL https://raw.githubusercontent.com/Hack-Me/Pocs_for_Multi_Versions/main/CVE-2015-9101/CVE-2015-9101_3.99.4 -o "${CASE5_DIR}/poc.wav"

cd "${BUILD_DIR}"
if [[ ! -d "lame-3.99.5" ]]; then
    curl -sL https://sourceforge.net/projects/lame/files/lame/3.99/lame-3.99.5.tar.gz/download -o lame-3.99.5.tar.gz
    tar -xzf lame-3.99.5.tar.gz
fi

# 1. Build bitcode using wllvm
cd "${BUILD_DIR}/lame-3.99.5"
make distclean 2>/dev/null || true
./configure CC=wllvm --disable-shared --disable-decoder
make -j16 CFLAGS="-g -O1"
extract-bc frontend/lame
cp frontend/lame.bc "${CASE5_DIR}/lame.bc"
cp frontend/lame "${CASE5_DIR}/lame_base"

# Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${CASE5_ID}"
export TARGET_GRAPH_OUT_DIR="${CASE5_DIR}"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes="target-graph" -disable-output "${CASE5_DIR}/lame.bc"

# 2. Build instrumented binary
# Recompile frontend and libmp3lame with trace runtime
make distclean
./configure CC=clang --disable-shared --disable-decoder
make -j16 \
    CFLAGS="-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard" \
    LDFLAGS="-fsanitize=address -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive"
cp frontend/lame "${CASE5_DIR}/lame_inst"

# Run PoC and capture trace
export TARGET_GRAPH_TRACE_FILE="${CASE5_DIR}/trace_crash.txt"
set +e
"${CASE5_DIR}/lame_inst" -f -V 9 "${CASE5_DIR}/poc.wav" /dev/null > /dev/null 2> "${CASE5_DIR}/crash_stderr.txt"
set -e
echo "Case 5 complete. Crash stderr lines: $(wc -l < "${CASE5_DIR}/crash_stderr.txt")"

chmod -R a+rw "${CASES_DIR}"

echo "=========================================================="
echo " All 5 Non-Benchmark Cases Built and Traced Successfully! "
echo "=========================================================="
