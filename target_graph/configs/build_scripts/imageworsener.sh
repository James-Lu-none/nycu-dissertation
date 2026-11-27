#!/usr/bin/env bash
# Build script for imageworsener-1.3.1 (Target: imagew)
set -euo pipefail

SRC_DIR="${1:?SRC_DIR required}"
OUT_DIR="${2:?OUT_DIR required}"
BUILD_ID="${3:?BUILD_ID required}"

TARGET_OUT="${OUT_DIR}/imagew"
mkdir -p "${TARGET_OUT}"
BUILD_TMP=$(mktemp -d /tmp/imagew_build_XXXXXX)
trap 'rm -rf "${BUILD_TMP}"' EXIT

cd "${BUILD_TMP}"
cp -r "${SRC_DIR}/." .

if [[ ! -f ./configure ]]; then
    if [[ -f ./scripts/autogen.sh ]]; then
        ./scripts/autogen.sh
    elif [[ -f ./autogen.sh ]]; then
        ./autogen.sh
    fi
fi

# Ensure libjpeg-dev is available so JPEG/Exif vulnerabilities (ASARUBBO-281..284) are compiled
if ! dpkg -s libjpeg-dev >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq libjpeg-dev
fi

# 1. Compile bitcode using wllvm
export LLVM_COMPILER=clang
./configure CC=wllvm CFLAGS="-g -O1" --disable-shared
make -j"$(nproc)"
extract-bc imagew
cp imagew.bc "${TARGET_OUT}/imagew.bc"
cp imagew "${TARGET_OUT}/imagew_base"

# 2. Run TargetGraphPass
export TARGET_GRAPH_BUILD_ID="${BUILD_ID}"
export TARGET_GRAPH_OUT_DIR="${TARGET_OUT}"
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-tag" -o "${TARGET_OUT}/imagew.bc" "${TARGET_OUT}/imagew.bc"

# 3. Instrument bitcode with TraceInstrumentPass and compile ASan binary (link libjpeg statically for container portability)
opt -load-pass-plugin=/usr/local/lib/BBIdentityPass.so -passes="bb-trace" -o "${TARGET_OUT}/imagew_trace.bc" "${TARGET_OUT}/imagew.bc"
clang -g -O1 -fsanitize=address -no-pie \
    "${TARGET_OUT}/imagew_trace.bc" \
    /usr/lib/x86_64-linux-gnu/libjpeg.a -lz -lm \
    -Wl,--whole-archive,/usr/local/lib/libtarget_graph_trace.a,--no-whole-archive \
    -o "${TARGET_OUT}/imagew_inst"

echo "[BUILD][imageworsener] Finished building imagew in ${TARGET_OUT}"
