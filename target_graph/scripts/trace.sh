#!/usr/bin/env bash
# Execute PoC against instrumented binary inside Docker and capture/symbolize execution trace.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CASE_ID=""

usage() {
    echo "Usage: $0 --case CASE_ID"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)
            CASE_ID="$2"; shift 2 ;;
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
if [[ ! -d "${CASE_DIR}" ]]; then
    echo "Error: Case directory ${CASE_DIR} does not exist. Run build.sh first." >&2
    exit 1
fi

echo "[TRACE] Running instrumented PoC execution for ${CASE_ID} inside Docker..."

docker run --rm \
    -v "${ROOT_DIR}:/workspace" \
    target-graph:llvm14 bash -c "
set -uo pipefail
CASE_DIR=\"/workspace/cases/${CASE_ID}\"
TRACE_FILE=\"\${CASE_DIR}/trace_crash.txt\"
STDERR_FILE=\"\${CASE_DIR}/crash_stderr.txt\"
export TARGET_GRAPH_TRACE_FILE=\"\${TRACE_FILE}\"
export ASAN_OPTIONS=\"abort_on_error=0:symbolize=1:strip_path_prefix=/workspace/:handle_segv=1\"

rm -f \"\${TRACE_FILE}\" \"\${STDERR_FILE}\"

case \"${CASE_ID}\" in
    \"lua-5.3.5_lua_CVE-2019-6706\")
        \"\${CASE_DIR}/lua_inst\" \"\${CASE_DIR}/poc.lua\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"cJSON-1.7.8_cJSON_CVE-2019-1010239\")
        \"\${CASE_DIR}/cjson_test_inst\" \"\${CASE_DIR}/poc.json\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"cJSON-1.7.8_cJSON_CVE-2019-11835\")
        \"\${CASE_DIR}/cjson_test_inst\" \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"jhead-3.04_jhead_issue54\")
        \"\${CASE_DIR}/jhead_inst\" -ds2020:01:01:1111111111111111111111111111111111111111 \"\${CASE_DIR}/dummy.jpg\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"jhead-3.04_jhead_issue55\")
        LONG_STR=\$(python3 -c 'print(\"A\" * 4096 + \"&i\" + \"B\" * 500)')
        \"\${CASE_DIR}/jhead_inst\" -te \"\$LONG_STR\" \"\${CASE_DIR}/dummy.jpg\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    jhead-*_jhead_*)
        JHEAD_POC=\"\${CASE_DIR}/poc\"
        if [[ ! -f \"\$JHEAD_POC\" && -f \"\${CASE_DIR}/poc.jpg\" ]]; then
            JHEAD_POC=\"\${CASE_DIR}/poc.jpg\"
        fi
        \"\${CASE_DIR}/jhead_inst\" -ds2020:01:01:1111111111111111111111111111111111111111 \"\$JHEAD_POC\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    libtiff-*_tiffcrop_*)
        \"\${CASE_DIR}/tiffcrop_inst\" -i \"\${CASE_DIR}/poc.tif\" /tmp/out.tif > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    libtiff-*_tiffsplit_*)
        \"\${CASE_DIR}/tiffsplit_inst\" \"\${CASE_DIR}/poc.tif\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    bento4-*_mp42aac_*)
        \"\${CASE_DIR}/mp42aac_inst\" \"\${CASE_DIR}/poc\" /tmp/out.aac > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    libtiff-*_tiffcp_*)
        \"\${CASE_DIR}/tiffcp_inst\" -i \"\${CASE_DIR}/poc.tif\" /tmp/out.tif > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    lame-*_lame_*)
        LAME_IN="\${CASE_DIR}/poc"
        if [[ ! -f "\$LAME_IN" && -f "\${CASE_DIR}/poc.wav" ]]; then
            LAME_IN="\${CASE_DIR}/poc.wav"
        fi
        \"\${CASE_DIR}/lame_inst\" \"\$LAME_IN\" /dev/null > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"libjpeg-2.0.4_cjpeg_CVE-2020-13790\")
        \"\${CASE_DIR}/cjpeg_inst\" \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    libming-*_swftophp_*)
        "\${CASE_DIR}/swftophp_inst" "\${CASE_DIR}/poc" > /dev/null 2> "\${STDERR_FILE}" || true
        ;;
    binutils-2.26_cxxfilt_CVE-2016-6131)
        POC_ARG=\$(cat "\${CASE_DIR}/poc")
        "\${CASE_DIR}/cxxfilt_inst" "\${POC_ARG}" > /dev/null 2> "\${STDERR_FILE}" || true
        ;;
    binutils-2.26_cxxfilt_*)
        "\${CASE_DIR}/cxxfilt_inst" < "\${CASE_DIR}/poc" > /dev/null 2> "\${STDERR_FILE}" || true
        ;;
    \"binutils-2.28_objdump_CVE-2017-8392\")
        \"\${CASE_DIR}/objdump_inst\" -SD \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"binutils-2.28_objdump_CVE-2017-8396\")
        \"\${CASE_DIR}/objdump_inst\" -W \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"binutils-2.28_objdump_CVE-2017-8397\")
        \"\${CASE_DIR}/objdump_inst\" -W \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"binutils-2.28_objdump_CVE-2017-8398\")
        \"\${CASE_DIR}/objdump_inst\" -W \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    binutils-2.28_objdump_*)
        \"\${CASE_DIR}/objdump_inst\" -d \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"binutils-2.28_objcopy_CVE-2017-8393\")
        \"\${CASE_DIR}/objcopy_inst\" --compress-debug-sections \"\${CASE_DIR}/poc\" /tmp/out_objcopy > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"binutils-2.28_objcopy_CVE-2017-8394\")
        \"\${CASE_DIR}/objcopy_inst\" -Gs \"\${CASE_DIR}/poc\" /tmp/out_objcopy > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"binutils-2.28_objcopy_CVE-2017-8395\"*|binutils-2.28_objcopy_*)
        \"\${CASE_DIR}/objcopy_inst\" --compress-debug-sections \"\${CASE_DIR}/poc\" /tmp/out_objcopy > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    libxml2-*_xmllint_*)
        \"\${CASE_DIR}/xmllint_inst\" --valid --noout \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    binutils-2.27_strip_*)
        \"\${CASE_DIR}/strip_inst\" -s \"\${CASE_DIR}/poc\" -o /tmp/out_strip > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    binutils-2.29_readelf_*)
        \"\${CASE_DIR}/readelf_inst\" -w \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    binutils-2.29_nm_*)
        \"\${CASE_DIR}/nm_inst\" -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    binutils-2.31.1_objdump_*)
        \"\${CASE_DIR}/objdump_inst\" --dwarf-check -C -g -f -dwarf -x \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    lrzip-*_lrzip_*)
        \"\${CASE_DIR}/lrzip_inst\" -t \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    zziplib-*_unzzipcat-mem_*)
        \"\${CASE_DIR}/unzzipcat-mem_inst\" \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    jasper-*_imginfo_*)
        \"\${CASE_DIR}/imginfo_inst\" -f \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    podofo-*_podofopdfinfo_*)
        \"\${CASE_DIR}/podofopdfinfo_inst\" \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    podofo-*_podofocolor_*)
        \"\${CASE_DIR}/podofocolor_inst\" \"\${CASE_DIR}/poc\" /tmp/out.pdf > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    podofo-*_podofotxtextract_*)
        \"\${CASE_DIR}/podofotxtextract_inst\" \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    podofo-*_podofotxt2pdf_*)
        \"\${CASE_DIR}/podofotxt2pdf_inst\" /tmp/out.pdf \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    imageworsener-*_imagew_*|imageworsener-*_imageworsener_*)
        \"\${CASE_DIR}/imagew_inst\" \"\${CASE_DIR}/poc\" /tmp/out.bmp -outfmt bmp > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    autotrace-*_autotrace_*)
        \"\${CASE_DIR}/autotrace_inst\" -output-file /dev/null \"\${CASE_DIR}/poc\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    *)
        echo \"Unknown case ID: ${CASE_ID}\" >&2
        exit 1
        ;;
esac

if [[ -f \"trace.txt\" && ! -s \"\${TRACE_FILE}\" ]]; then
    cp trace.txt \"\${TRACE_FILE}\" 2>/dev/null || true
fi

chmod -R a+rw \"\${CASE_DIR}\"
"

TRACE_LINES=$(wc -l < "${CASE_DIR}/trace_crash.txt" 2>/dev/null || echo 0)
STDERR_LINES=$(wc -l < "${CASE_DIR}/crash_stderr.txt" 2>/dev/null || echo 0)

if [[ ${TRACE_LINES} -eq 0 ]]; then
    echo "Error: Trace file is empty for ${CASE_ID}!" >&2
    exit 1
fi

echo "[TRACE] PoC executed. Trace lines: ${TRACE_LINES}, Crash stderr lines: ${STDERR_LINES}"

# Verify symbolization using Python
PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"
"${PYTHON_BIN}" -c "
from pathlib import Path
from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.tracing.symbolizer import trace_to_basic_blocks

case_dir = Path('${CASE_DIR}')
bb_map_file = case_dir / 'bb_map.jsonl'
if bb_map_file.exists():
    mapper = BasicBlockMapper(bb_map_file)
    inst_bin = list(case_dir.glob('*_inst'))[0]
    trace_file = case_dir / 'trace_crash.txt'

    bbs = trace_to_basic_blocks(trace_file, inst_bin, mapper)
    print(f'[SUCCESS] Trace symbolized: {len(bbs)} executed BB events, {len(set(bbs))} unique basic blocks.')
else:
    print(f'[INFO] Trace generated. Run graph.sh first to produce bb_map.jsonl for symbolization.')
"
