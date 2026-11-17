#!/usr/bin/env bash
# Extract and export canonical Parquet program graph for a case.
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
if [[ ! -d "${CASE_DIR}" ]]; then
    echo "Error: Case directory ${CASE_DIR} does not exist. Run build.sh first." >&2
    exit 1
fi

# Locate bitcode file
BC_FILE=""
for f in "${CASE_DIR}"/*.bc; do
    if [[ -f "$f" ]]; then
        BC_FILE="$(basename "$f")"
        break
    fi
done

if [[ -z "${BC_FILE}" ]]; then
    echo "Error: No .bc file found in ${CASE_DIR}." >&2
    exit 1
fi

echo "[GRAPH] Running TargetGraphPass on ${CASE_ID} (${BC_FILE}) inside Docker..."

# Run pass inside Docker
docker run --rm \
    -v "${ROOT_DIR}:/workspace" \
    target-graph:llvm14 bash -c "
set -euo pipefail
CASE_DIR=\"/workspace/cases/${CASE_ID}\"
BC_PATH=\"\${CASE_DIR}/${BC_FILE}\"

rm -f \"\${CASE_DIR}/raw_nodes.jsonl\" \"\${CASE_DIR}/raw_edges.jsonl\" \"\${CASE_DIR}/bb_map.jsonl\" \"\${CASE_DIR}/pass_summary.json\"

export TARGET_GRAPH_BUILD_ID=\"${CASE_ID}\"
export TARGET_GRAPH_OUT_DIR=\"\${CASE_DIR}\"
opt -load-pass-plugin=/usr/local/lib/TargetGraphPass.so -passes=\"target-graph\" -disable-output \"\${BC_PATH}\"

chmod -R a+rw \"\${CASE_DIR}\"
"

echo "[GRAPH] Exporting raw JSONL to canonical Parquet bundle..."
PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"
"${PYTHON_BIN}" -m target_graph.analysis.export \
    --raw-dir "${CASE_DIR}" \
    --output-dir "${CASE_DIR}/parquet" \
    --build-id "${CASE_ID}" \
    --llvm-version "14.0"

echo "[SUCCESS] Canonical Parquet graph bundle generated and validated for ${CASE_ID}:"
ls -lh "${CASE_DIR}/parquet"
