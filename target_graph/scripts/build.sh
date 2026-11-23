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
PARENT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"

echo "[BUILD] Building case: ${CASE_ID} inside Docker container target-graph:llvm14..."

docker run --rm \
    -v "${ROOT_DIR}:/workspace" \
    -v "${PARENT_DIR}:/dissertation:ro" \
    target-graph:llvm14 bash -c "
set -euo pipefail
export CASE_ID=\"${CASE_ID}\"
export LLVM_COMPILER=clang
BUILD_DIR=\"/workspace/build_test\"
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

    \"cJSON-1.7.8_cJSON_CVE-2019-11835\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"cjson_src\" ]]; then
            git clone --depth 1 -b v1.7.8 https://github.com/DaveGamble/cJSON.git cjson_src
        fi
        cd cjson_src
        cat << 'DRIVEREOC' > cjson_minify_test.c
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

    cJSON_Minify(data);
    free(data);
    return 0;
}
DRIVEREOC
        clang -g -O1 -emit-llvm -c cJSON.c cjson_minify_test.c
        llvm-link -o \"\${CASE_DIR}/cjson_test.bc\" cJSON.bc cjson_minify_test.bc
        clang -g -O1 -no-pie cJSON.c cjson_minify_test.c -o \"\${CASE_DIR}/cjson_test_base\" -lm
        clang -g -O1 -no-pie \
            -fsanitize=address \
            -fsanitize-coverage=trace-pc-guard,no-prune \
            cJSON.c cjson_minify_test.c \
            -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
            -o \"\${CASE_DIR}/cjson_test_inst\" -lm
        printf '/* unterminated' > \"\${CASE_DIR}/poc\"
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
        python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('ffd8ffe000104a46494600010101006000600000ffdb004300ffc0000b080001000101011100ffda0008010100003f00bf00ffd9'))\" > \"\${CASE_DIR}/dummy.jpg\"
        ;;

    \"jhead-3.04_jhead_issue55\")
        cd \"\${BUILD_DIR}\"
        if [[ ! -d \"jhead_issue55_src\" ]]; then
            git clone https://github.com/Matthias-Wandel/jhead.git jhead_issue55_src
            cd jhead_issue55_src
            git checkout -f e6294430d382fc49de41299b263e291b057890f7~1
            cd ..
        fi
        cd jhead_issue55_src
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
        cp \"/workspace/cases/jhead-3.04_jhead_issue54/dummy.jpg\" \"\${CASE_DIR}/dummy.jpg\"
        ;;

    \"libtiff-4.0.6_tiffcrop_CVE-2016-10271\")
        if [[ -f \"/workspace/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10092/tiffcrop.bc\" ]]; then
            cp \"/workspace/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10092/tiffcrop.bc\" \"\${CASE_DIR}/tiffcrop.bc\"
            cp \"/workspace/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10092/tiffcrop_base\" \"\${CASE_DIR}/tiffcrop_base\"
            cp \"/workspace/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10092/tiffcrop_inst\" \"\${CASE_DIR}/tiffcrop_inst\"
            if [[ -d \"/workspace/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10092/src\" ]]; then
                cp -r \"/workspace/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10092/src\" \"\${CASE_DIR}/\"
            fi
        fi
        if [[ -f \"\${BUILD_DIR}/poc_10271\" ]]; then
            cp \"\${BUILD_DIR}/poc_10271\" \"\${CASE_DIR}/poc.tif\"
        else
            curl -sL https://raw.githubusercontent.com/mudongliang/LinuxFlaw/master/CVE-2016-10271/00100-libtiff-heapoverflow-_TIFFFax3fillruns -o \"\${CASE_DIR}/poc.tif\"
        fi
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

    \"libjpeg-2.0.4_cjpeg_CVE-2020-13790\")
        cd \"\${BUILD_DIR}\"
        rm -rf libjpeg204_src
        if [[ -d \"/dissertation/bench/src/61ed23612b42/libjpeg-turbo-2.0.4\" ]]; then
            cp -r /dissertation/bench/src/61ed23612b42/libjpeg-turbo-2.0.4 libjpeg204_src
        else
            git clone --depth 1 -b 2.0.4 https://github.com/libjpeg-turbo/libjpeg-turbo.git libjpeg204_src
        fi
        cd libjpeg204_src
        mkdir -p \"\${CASE_DIR}/src\"
        cp -r *.c *.h \"\${CASE_DIR}/src/\" 2>/dev/null || true
        mkdir -p build_wllvm && cd build_wllvm
        cmake .. -G\"Unix Makefiles\" -DCMAKE_C_COMPILER=wllvm -DCMAKE_C_FLAGS=\"-g -O1\" -DENABLE_SHARED=OFF -DWITH_SIMD=OFF
        make -j16 cjpeg-static
        extract-bc cjpeg-static
        cp cjpeg-static.bc \"\${CASE_DIR}/cjpeg.bc\"
        cp cjpeg-static \"\${CASE_DIR}/cjpeg_base\"
        cd \"\${BUILD_DIR}/libjpeg204_src\"
        mkdir -p build_inst && cd build_inst
        cmake .. -G\"Unix Makefiles\" \
            -DCMAKE_C_COMPILER=clang \
            -DCMAKE_C_FLAGS=\"-g -O1 -fsanitize=address -fsanitize-coverage=trace-pc-guard,no-prune -no-pie\" \
            -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address -no-pie -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive\" \
            -DENABLE_SHARED=OFF -DWITH_SIMD=OFF
        make -j16 cjpeg-static
        cp cjpeg-static \"\${CASE_DIR}/cjpeg_inst\"
        if [[ -f \"/dissertation/bench/target/benchmark-project/libjpeg-2.0.4/poc/2020-13790\" ]]; then
            cp /dissertation/bench/target/benchmark-project/libjpeg-2.0.4/poc/2020-13790 \"\${CASE_DIR}/poc\"
        fi
        ;;

    \"libming-4.8_swftophp_\"*)
        cd \"\${BUILD_DIR}\"
        if [[ -f \"/workspace/cases/libming-4.8_swftophp_CVE-2018-7868/swftophp.bc\" ]]; then
            cp \"/workspace/cases/libming-4.8_swftophp_CVE-2018-7868/swftophp.bc\" \"\${CASE_DIR}/swftophp.bc\"
            cp \"/workspace/cases/libming-4.8_swftophp_CVE-2018-7868/swftophp_base\" \"\${CASE_DIR}/swftophp_base\"
            cp \"/workspace/cases/libming-4.8_swftophp_CVE-2018-7868/swftophp_inst\" \"\${CASE_DIR}/swftophp_inst\"
            if [[ -d \"/workspace/cases/libming-4.8_swftophp_CVE-2018-7868/src\" ]]; then
                cp -r \"/workspace/cases/libming-4.8_swftophp_CVE-2018-7868/src\" \"\${CASE_DIR}/\"
            fi
        else
            rm -rf libming48_src
            if [[ -d \"/dissertation/bench/src/b8a5c20ca76d/libming\" ]]; then
                cp -r /dissertation/bench/src/b8a5c20ca76d/libming libming48_src
            else
                git clone --depth 1 -b ming-0_4_8 https://github.com/libming/libming.git libming48_src
            fi
            cd libming48_src
            mkdir -p \"\${CASE_DIR}/src\"
            cp -r util/*.c util/*.h src/*.h src/blocks/*.c src/blocks/*.h \"\${CASE_DIR}/src/\" 2>/dev/null || true
            SRCS=\"util/outputscript.c util/main.c util/action.c util/blocktypes.c util/decompile.c util/parser.c util/read.c util/vasprintf.c src/blocks/error.c\"
            INCS=\"-Isrc -Iutil -DSWFPHP\"
            clang -g -O1 \${INCS} -emit-llvm -c \${SRCS}
            llvm-link -o \"\${CASE_DIR}/swftophp.bc\" outputscript.bc main.bc action.bc blocktypes.bc decompile.bc parser.bc read.bc vasprintf.bc error.bc
            clang -g -O1 \${INCS} -no-pie \${SRCS} -o \"\${CASE_DIR}/swftophp_base\" -lm -lz
            clang -g -O1 \${INCS} -no-pie \
                -fsanitize=address \
                -fsanitize-coverage=trace-pc-guard,no-prune \
                \${SRCS} \
                -Wl,--whole-archive /usr/local/lib/libtarget_graph_trace.a -Wl,--no-whole-archive \
                -o \"\${CASE_DIR}/swftophp_inst\" -lm -lz
        fi
        case \"\${CASE_ID}\" in
            \"libming-4.8_swftophp_CVE-2018-7868\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-7868-github\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2018-8807\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-8807\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2018-8962\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-8962-a\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2018-11095\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-11095-github\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2018-11225\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-11225\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2018-11226\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-11226\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2019-12982\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2019-12982\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2018-20427\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2018-20427\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.8_swftophp_CVE-2020-6628\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.8/poc/2020-6628\" \"\${CASE_DIR}/poc\" ;;
        esac
        ;;

    \"libming-4.7_swftophp_\"*)
        cd \"\${BUILD_DIR}\"
        if [[ -f \"/workspace/cases/libming-4.7.1_swftophp_CVE-2017-7578/swftophp.bc\" ]]; then
            cp \"/workspace/cases/libming-4.7.1_swftophp_CVE-2017-7578/swftophp.bc\" \"\${CASE_DIR}/swftophp.bc\"
            cp \"/workspace/cases/libming-4.7.1_swftophp_CVE-2017-7578/swftophp_base\" \"\${CASE_DIR}/swftophp_base\"
            cp \"/workspace/cases/libming-4.7.1_swftophp_CVE-2017-7578/swftophp_inst\" \"\${CASE_DIR}/swftophp_inst\"
            if [[ -d \"/workspace/cases/libming-4.7.1_swftophp_CVE-2017-7578/src\" ]]; then
                cp -r \"/workspace/cases/libming-4.7.1_swftophp_CVE-2017-7578/src\" \"\${CASE_DIR}/\"
            fi
        fi
        case \"\${CASE_ID}\" in
            \"libming-4.7_swftophp_CVE-2017-11728\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.7/poc/2017-11728\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.7_swftophp_CVE-2017-11729\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.7/poc/2017-11729\" \"\${CASE_DIR}/poc\" ;;
            \"libming-4.7_swftophp_CVE-2017-9988\")
                cp \"/dissertation/bench/target/benchmark-project/libming-4.7/poc/2017-9988-github\" \"\${CASE_DIR}/poc\" ;;
        esac
        ;;

    \"binutils-2.26_cxxfilt_\"*)
        cd \"\${BUILD_DIR}\"
        if [[ -f \"/workspace/cases/binutils-2.26_cxxfilt_CVE-2016-4487/cxxfilt.bc\" ]]; then
            cp \"/workspace/cases/binutils-2.26_cxxfilt_CVE-2016-4487/cxxfilt.bc\" \"\${CASE_DIR}/cxxfilt.bc\"
            cp \"/workspace/cases/binutils-2.26_cxxfilt_CVE-2016-4487/cxxfilt_base\" \"\${CASE_DIR}/cxxfilt_base\"
            cp \"/workspace/cases/binutils-2.26_cxxfilt_CVE-2016-4487/cxxfilt_inst\" \"\${CASE_DIR}/cxxfilt_inst\"
            if [[ -d \"/workspace/cases/binutils-2.26_cxxfilt_CVE-2016-4487/src\" ]]; then
                cp -r \"/workspace/cases/binutils-2.26_cxxfilt_CVE-2016-4487/src\" \"\${CASE_DIR}/\"
            fi
        fi
        case \"\${CASE_ID}\" in
            \"binutils-2.26_cxxfilt_CVE-2016-4490\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.26/poc/2016-4490\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.26_cxxfilt_CVE-2016-4491\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.26/poc/2016-4491\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.26_cxxfilt_CVE-2016-4492\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.26/poc/2016-4492-case1\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.26_cxxfilt_CVE-2016-6131\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.26/poc/2016-6131\" \"\${CASE_DIR}/poc\" ;;
        esac
        ;;

    \"binutils-2.28_\"*)
        cd \"\${BUILD_DIR}\"
        SRC_DIR=\"\${BUILD_DIR}/binutils228_test/src\"
        BINS_DIR=\"\${BUILD_DIR}/binutils228_bins\"
        case \"\${CASE_ID}\" in
            \"binutils-2.28_objdump_\"*)
                cp \"\${BINS_DIR}/objdump.bc\" \"\${CASE_DIR}/objdump.bc\"
                cp \"\${BINS_DIR}/objdump_base\" \"\${CASE_DIR}/objdump_base\"
                cp \"\${BINS_DIR}/objdump_inst\" \"\${CASE_DIR}/objdump_inst\"
                ;;
            \"binutils-2.28_objcopy_\"*)
                cp \"\${BINS_DIR}/objcopy.bc\" \"\${CASE_DIR}/objcopy.bc\"
                cp \"\${BINS_DIR}/objcopy_base\" \"\${CASE_DIR}/objcopy_base\"
                cp \"\${BINS_DIR}/objcopy_inst\" \"\${CASE_DIR}/objcopy_inst\"
                ;;
        esac
        if [[ -d \"\${SRC_DIR}\" ]]; then
            mkdir -p \"\${CASE_DIR}/src\"
            cp -r \"\${SRC_DIR}/bfd\"/*.c \"\${SRC_DIR}/bfd\"/*.h \"\${SRC_DIR}/binutils\"/*.c \"\${SRC_DIR}/binutils\"/*.h \"\${CASE_DIR}/src/\" 2>/dev/null || true
        fi
        case \"\${CASE_ID}\" in
            \"binutils-2.28_objdump_CVE-2017-8392\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objdump/2017-8392\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.28_objdump_CVE-2017-8396\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objdump/2017-8396\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.28_objdump_CVE-2017-8397\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objdump/2017-8397\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.28_objdump_CVE-2017-8398\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objdump/2017-8398\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.28_objcopy_CVE-2017-8393\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objcopy/2017-8393\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.28_objcopy_CVE-2017-8394\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objcopy/2017-8394\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.28_objcopy_CVE-2017-8395\")
                cp \"/dissertation/bench/target/benchmark-project/binutils-2.28/poc-objcopy/2017-8395-a\" \"\${CASE_DIR}/poc\" ;;
        esac
        ;;

    \"binutils-2.29_\"*)
        cd \"\${BUILD_DIR}\"
        SRC_DIR=\"\${BUILD_DIR}/binutils229_build/src\"
        BINS_DIR=\"\${BUILD_DIR}/binutils229_bins\"
        case \"\${CASE_ID}\" in
            \"binutils-2.29_nm_\"*)
                cp \"\${BINS_DIR}/nm.bc\" \"\${CASE_DIR}/nm.bc\"
                cp \"\${BINS_DIR}/nm_base\" \"\${CASE_DIR}/nm_base\"
                cp \"\${BINS_DIR}/nm_inst\" \"\${CASE_DIR}/nm_inst\"
                ;;
            \"binutils-2.29_readelf_\"*)
                cp \"\${BINS_DIR}/readelf.bc\" \"\${CASE_DIR}/readelf.bc\"
                cp \"\${BINS_DIR}/readelf_base\" \"\${CASE_DIR}/readelf_base\"
                cp \"\${BINS_DIR}/readelf_inst\" \"\${CASE_DIR}/readelf_inst\"
                ;;
        esac
        if [[ -d \"\${SRC_DIR}\" ]]; then
            mkdir -p \"\${CASE_DIR}/src\"
            cp -r \"\${SRC_DIR}/bfd\"/*.c \"\${SRC_DIR}/bfd\"/*.h \"\${SRC_DIR}/binutils\"/*.c \"\${SRC_DIR}/binutils\"/*.h \"\${CASE_DIR}/src/\" 2>/dev/null || true
        fi
        case \"\${CASE_ID}\" in
            \"binutils-2.29_nm_CVE-2017-15938\")
                cp \"\${BUILD_DIR}/linuxflaw_poc/CVE-2017-15938/00381-binutils-invalidread-find_abstract_instance_name\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.29_nm_CVE-2017-15020\")
                cp \"\${BUILD_DIR}/linuxflaw_poc/CVE-2017-15020/00376-binutils-heapoverflow-parse_die\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.29_nm_CVE-2017-15939\")
                cp \"\${BUILD_DIR}/linuxflaw_poc/CVE-2017-15939/00380-binutils-NULLptr-concat_filename\" \"\${CASE_DIR}/poc\" ;;
            \"binutils-2.29_readelf_CVE-2017-16828\")
                cp \"\${BUILD_DIR}/asarubbo_poc/00382-binutils-heapoverflow-get_line_filename_and_dirname\" \"\${CASE_DIR}/poc\" ;;
        esac
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
