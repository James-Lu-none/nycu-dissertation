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

rm -f \"\${TRACE_FILE}\" \"\${STDERR_FILE}\"

case \"${CASE_ID}\" in
    \"lua-5.3.5_lua_CVE-2019-6706\")
        \"\${CASE_DIR}/lua_inst\" \"\${CASE_DIR}/poc.lua\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"cJSON-1.7.8_cJSON_CVE-2019-1010239\")
        \"\${CASE_DIR}/cjson_test_inst\" \"\${CASE_DIR}/poc.json\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"jhead-3.04_jhead_issue54\")
        \"\${CASE_DIR}/jhead_inst\" -ds2020:01:01:1111111111111111111111111111111111111111 \"\${CASE_DIR}/dummy.jpg\" > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"libtiff-4.0.6_tiffcrop_CVE-2016-10092\")
        \"\${CASE_DIR}/tiffcrop_inst\" -i \"\${CASE_DIR}/poc.tif\" /tmp/out.tif > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    \"lame-3.99.5_lame_CVE-2015-9101\")
        \"\${CASE_DIR}/lame_inst\" \"\${CASE_DIR}/poc.wav\" /dev/null > /dev/null 2> \"\${STDERR_FILE}\" || true
        ;;
    *)
        echo \"Unknown case ID: ${CASE_ID}\" >&2
        exit 1
        ;;
esac

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
mapper = BasicBlockMapper(case_dir / 'bb_map.jsonl')
inst_bin = list(case_dir.glob('*_inst'))[0]
trace_file = case_dir / 'trace_crash.txt'

bbs = trace_to_basic_blocks(trace_file, inst_bin, mapper)
print(f'[SUCCESS] Trace symbolized: {len(bbs)} executed BB events, {len(set(bbs))} unique basic blocks.')
"
