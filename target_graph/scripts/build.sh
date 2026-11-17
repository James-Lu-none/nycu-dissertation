#!/usr/bin/env bash
# Build bitcode and instrumented binaries for a benchmark case inside Docker.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CASE_ID=""
FORCE=false

usage() {
    echo "Usage: $0 --case CASE_ID [--force]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)
            CASE_ID="$2"; shift 2 ;;
        --force)
            FORCE=true; shift ;;
        -h|--help)
            usage ;;
        *)
            echo "Unknown argument: $1" >&2
            usage ;;
    esac
done

if [[ -z "${CASE_ID}" ]]; then
    echo "Error: --case is required." >&2
    usage
fi

CASE_DIR="${ROOT_DIR}/cases/${CASE_ID}"
mkdir -p "${CASE_DIR}"

echo "[BUILD] Building case: ${CASE_ID} inside Docker container target-graph:llvm14..."

docker run --rm \
    -v "${ROOT_DIR}:/workspace" \
    target-graph:llvm14 bash -c "
set -euo pipefail
export LLVM_COMPILER=clang
BUILD_DIR="/workspace/build_test"
CASES_DIR=\"/workspace/cases\"
CASE_DIR=\"\${CASES_DIR}/${CASE_ID}\"
mkdir -p \"\${BUILD_DIR}\" \"\${CASE_DIR}\"

case \"${CASE_ID}\" in
    \"lua-5.3.5_lua_CVE-2019-6706\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"lua_src\" ]]; then
            git clone --depth 1 -b v5.3.5 https://github.com/lua/lua.git lua_src
        fi
        cd lua_src
        clang -g -O1 -emit-llvm -c \$(ls *.c | grep -v luac.c)
        llvm-link -o \"\${CASE_DIR}/lua.bc\" \$(ls *.bc | grep -v luac.bc)
        clang -g -O1 -no-pie \$(ls *.c | grep -v luac.c) -o \"\${CASE_DIR}/lua_base\" -lm -ldl
        clang -g -O1 -no-pie \
            -fsanitize=address \
            -fsanitize-coverage=trace-pc-guard,no-prune \
            \$(ls *.c | grep -v luac.c) \
            -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
            -o \"\${CASE_DIR}/lua_inst\" -lm -ldl
        cat << 'POCTEXT' > \"\${CASE_DIR}/poc.lua\"
f = load(function() end); debug.upvaluejoin(f, 1, f, 1)
POCTEXT
        ;;

    \"cJSON-1.7.8_cJSON_CVE-2019-1010239\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"cjson_src\" ]]; then
            git clone --depth 1 -b v1.7.8 https://github.com/DaveGamble/cJSON.git cjson_src
        fi
        cd cjson_src
        cat << 'DRIVEREOC' > cjson_test.c
#include <stdio.h>
#include <stdlib.h>
#include \"cJSON.h\"

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], \"rb\");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    fread(data, 1, len, f);
    data[len] = '\\0';
    fclose(f);

    cJSON *json = cJSON_Parse(data);
    if (json) {
        cJSON_GetObjectItemCaseSensitive(json, \"test\");
        cJSON_Delete(json);
    }
    free(data);
    return 0;
}
DRIVEREOC
        clang -g -O1 -emit-llvm -c cJSON.c cjson_test.c
        llvm-link -o \"\${CASE_DIR}/cjson_test.bc\" cJSON.bc cjson_test.bc
        clang -g -O1 -no-pie cJSON.c cjson_test.c -o \"\${CASE_DIR}/cjson_test_base\" -lm
        clang -g -O1 -no-pie \
            -fsanitize=address \
            -fsanitize-coverage=trace-pc-guard,no-prune \
            cJSON.c cjson_test.c \
            -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
            -o \"\${CASE_DIR}/cjson_test_inst\" -lm
        echo -n '[1, 2, 3]' > \"\${CASE_DIR}/poc.json\"
        ;;

    \"jhead-3.04_jhead_issue54\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"jhead_src\" ]]; then
            git clone https://github.com/Matthias-Wandel/jhead.git jhead_src
            cd jhead_src
            git checkout bf9a18789e5b6125f4a5b928f98b569a16076a96~1
            cd ..
        fi
        cd jhead_src
        SRCS=\"jhead.c jpgfile.c jpgqguess.c paths.c exif.c iptc.c gpsinfo.c makernote.c\"
        clang -g -O1 -emit-llvm -c \${SRCS}
        llvm-link -o \"\${CASE_DIR}/jhead.bc\" *.bc
        clang -g -O1 -no-pie \${SRCS} -o \"\${CASE_DIR}/jhead_base\" -lm
        clang -g -O1 -no-pie \
            -fsanitize=address \
            -fsanitize-coverage=trace-pc-guard,no-prune \
            \${SRCS} \
            -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
            -o \"\${CASE_DIR}/jhead_inst\" -lm
        printf '\\xff\\xd8\\xff\\xe0\\x00\\x10JFIF\\x00\\x01\\x01\\x01\\x00`\\x00`\\x00\\x00\\xff\\xdb\\x00C\\x00\\xff\\xc0\\x00\\x0b\\x08\\x00\\x01\\x00\\x01\\x01\\x01\\x11\\x00\\xff\\xda\\x00\\x08\\x01\\x01\\x00\\x00?\\x00\\xbf\\x00\\xff\\xd9' > \"\${CASE_DIR}/dummy.jpg\"
        ;;

    \"libtiff-4.0.6_tiffcrop_CVE-2016-10092\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"libtiff_src\" ]]; then
            git clone --depth 1 -b v4.0.6 https://gitlab.com/libtiff/libtiff.git libtiff_src
        fi
        cd libtiff_src
        rm -rf build_wllvm build_inst
        mkdir -p build_wllvm && cd build_wllvm
        cmake .. -DCMAKE_C_COMPILER=wllvm -DCMAKE_C_FLAGS=\"-g -O1\" -DBUILD_SHARED_LIBS=OFF
        make -j16 tiffcrop
        extract-bc tools/tiffcrop
        cp tools/tiffcrop.bc \"\${CASE_DIR}/tiffcrop.bc\"
        cp tools/tiffcrop \"\${CASE_DIR}/tiffcrop_base\"
        cd \"\${BUILD_DIR}/libtiff_src\"
        mkdir -p build_inst && cd build_inst
        cmake .. \
            -DCMAKE_C_COMPILER=clang \
            -DCMAKE_C_FLAGS=\"-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie\" \
            -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive\" \
            -DBUILD_SHARED_LIBS=OFF
        make -j16 tiffcrop
        cp tools/tiffcrop \"\${CASE_DIR}/tiffcrop_inst\"
        curl -sL https://raw.githubusercontent.com/Hack-Me/Pocs_for_Multi_Versions/main/CVE-2016-10092/CVE-2016-10092_v4.0.6 -o \"\${CASE_DIR}/poc.tif\"
        ;;

    \"lame-3.99.5_lame_CVE-2015-9101\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"lame_base_src\" ]]; then
            mkdir -p lame_base_src && curl -sL https://downloads.sourceforge.net/project/lame/lame/3.99/lame-3.99.5.tar.gz | tar -xz -C lame_base_src --strip-components=1
        fi
        cd lame_base_src
        if [[ ! -f \"\${CASE_DIR}/lame.bc\" ]]; then
            make distclean 2>/dev/null || true
            ./configure CC=wllvm --disable-shared --disable-decoder
            make -j16 CFLAGS=\"-g -O1\"
            extract-bc frontend/lame
            cp frontend/lame.bc \"\${CASE_DIR}/lame.bc\"
            cp frontend/lame \"\${CASE_DIR}/lame_base\"
        fi
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"lame_inst_src\" ]]; then
            mkdir -p lame_inst_src && curl -sL https://downloads.sourceforge.net/project/lame/lame/3.99/lame-3.99.5.tar.gz | tar -xz -C lame_inst_src --strip-components=1
        fi
        cd lame_inst_src
        if [[ ! -f \"\${CASE_DIR}/lame_inst\" ]]; then
            make distclean 2>/dev/null || true
            ./configure CC=clang --disable-shared --disable-decoder \
                CFLAGS=\"-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie\" \
                LDFLAGS=\"-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive\"
            make -j16
            cp frontend/lame \"\${CASE_DIR}/lame_inst\"
        fi
        curl -sL https://raw.githubusercontent.com/Hack-Me/Pocs_for_Multi_Versions/main/CVE-2015-9101/CVE-2015-9101_3.99.4 -o \"\${CASE_DIR}/poc.wav\"
        ;;

    *)
        echo \"Unknown case ID: ${CASE_ID}\" >&2
        exit 1
        ;;
esac

chmod -R a+rw \"\${CASE_DIR}\"
"

echo "[SUCCESS] Build completed for ${CASE_ID}."
ls -lh "${CASE_DIR}"/*.bc "${CASE_DIR}"/*_inst "${CASE_DIR}"/*_base
