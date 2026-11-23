#!/usr/bin/env bash
# ==============================================================================
# run_all.sh - End-to-end reproducible pipeline for TargetGraph benchmark cases.
#
# Steps supported:
#   1. graph  - Extract Analysis V2 instruction/BB graph via Docker (target-graph:llvm14)
#   2. trace  - Execute PoC inside Docker, capture crash trace, symbolize and slice
#   3. audit  - Run strict label yield & coverage audit over all cases
#   4. all    - Run graph -> trace -> audit sequentially
#
# Usage:
#   ./scripts/run_all.sh [--stage all|graph|trace|audit] [--config PATH] [--jobs N] [--force]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

STAGE="all"
CONFIG_FILE="${ROOT_DIR}/configs/projects/cases.yaml"
CASES_ROOT="${ROOT_DIR}/cases"
REPORTS_DIR="${ROOT_DIR}/reports"
JOBS=4
FORCE=false
SPECIFIC_CASES=()

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --stage STAGE         Pipeline stage to run: 'all', 'graph', 'trace', 'audit' (default: all)
  --config PATH         Path to cases YAML config (default: configs/projects/cases.yaml)
  --cases-root DIR      Root directory containing case folders (default: cases)
  --cases ID [ID ...]   Specific case IDs to process (default: all cases in config)
  --jobs N, -j N        Parallel worker jobs for graph/trace (default: 4)
  --force               Force rerun even if output artifacts already exist
  -h, --help            Show this help message and exit

Examples:
  $0 --stage all
  $0 --stage trace --jobs 8
  $0 --stage audit
  $0 --cases bento4-1.5.0_mp42aac_ASARUBBO-336 --stage trace
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stage)
            STAGE="$2"; shift 2 ;;
        --config)
            CONFIG_FILE="$2"; shift 2 ;;
        --cases-root)
            CASES_ROOT="$2"; shift 2 ;;
        --jobs|-j)
            JOBS="$2"; shift 2 ;;
        --force)
            FORCE=true; shift ;;
        --cases)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                SPECIFIC_CASES+=("$1")
                shift
            done
            ;;
        -h|--help)
            usage ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            usage ;;
    esac
done

if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "Error: Cases configuration file not found at ${CONFIG_FILE}" >&2
    exit 1
fi

PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

echo "================================================================================"
echo " TargetGraph Pipeline Runner"
echo " Stage:       ${STAGE}"
echo " Config:      ${CONFIG_FILE}"
echo " Cases Root:  ${CASES_ROOT}"
echo " Concurrency: ${JOBS} jobs"
echo " Force Rerun: ${FORCE}"
echo " Python:      ${PYTHON_BIN}"
echo "================================================================================"

# Extract case list
if [[ ${#SPECIFIC_CASES[@]} -gt 0 ]]; then
    CASE_LIST=("${SPECIFIC_CASES[@]}")
else
    # Parse case_id from YAML using Python
    CASE_LIST=($("${PYTHON_BIN}" -c "
import yaml
with open('${CONFIG_FILE}', 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)
cases = [c['case_id'] for c in data.get('cases', [])]
print(' '.join(cases))
"))
fi

TOTAL_CASES=${#CASE_LIST[@]}
echo "[INFO] Loaded ${TOTAL_CASES} target cases."

# Function: Run Graph V2 for a single case
run_single_graph() {
    local case_id="$1"
    local cdir="${CASES_ROOT}/${case_id}"
    if [[ ! -d "${cdir}" ]]; then
        echo "[GRAPH][SKIP] ${case_id}: directory not found"
        return 0
    fi
    if [[ "${FORCE}" != "true" && -f "${cdir}/analysis_v2_nodes.jsonl" && -f "${cdir}/analysis_v2_edges.jsonl" ]]; then
        return 0
    fi
    "${SCRIPT_DIR}/graph_v2.sh" --case "${case_id}" > /dev/null 2>&1 || {
        echo "[GRAPH][FAIL] ${case_id}" >&2
        return 1
    }
}
export -f run_single_graph
export SCRIPT_DIR CASES_ROOT FORCE

# Function: Run Trace for a single case
run_single_trace() {
    local case_id="$1"
    local cdir="${CASES_ROOT}/${case_id}"
    if [[ ! -d "${cdir}" ]]; then
        echo "[TRACE][SKIP] ${case_id}: directory not found"
        return 0
    fi
    if [[ "${FORCE}" != "true" && -f "${cdir}/trace_crash.txt" && -s "${cdir}/trace_crash.txt" && -f "${cdir}/dep_slice.json" ]]; then
        return 0
    fi
    "${SCRIPT_DIR}/trace.sh" --case "${case_id}" > /dev/null 2>&1 || {
        echo "[TRACE][FAIL] ${case_id}" >&2
        return 1
    }
}
export -f run_single_trace

# ------------------------------------------------------------------------------
# Stage 1: Graph Extraction (V2)
# ------------------------------------------------------------------------------
if [[ "${STAGE}" == "all" || "${STAGE}" == "graph" ]]; then
    echo ""
    echo "--- [STAGE 1: GRAPH EXTRACTION (Analysis V2)] ---"
    START_TIME=$(date +%s)
    printf "%s\n" "${CASE_LIST[@]}" | xargs -I {} -P "${JOBS}" bash -c 'run_single_graph "$@"' _ {}
    DURATION=$(( $(date +%s) - START_TIME ))
    echo "[STAGE 1 COMPLETE] Graph extraction finished in ${DURATION}s."
fi

# ------------------------------------------------------------------------------
# Stage 2: Trace Execution & Slicing
# ------------------------------------------------------------------------------
if [[ "${STAGE}" == "all" || "${STAGE}" == "trace" ]]; then
    echo ""
    echo "--- [STAGE 2: TRACE EXECUTION & SLICING] ---"
    START_TIME=$(date +%s)
    printf "%s\n" "${CASE_LIST[@]}" | xargs -I {} -P "${JOBS}" bash -c 'run_single_trace "$@"' _ {}
    DURATION=$(( $(date +%s) - START_TIME ))
    echo "[STAGE 2 COMPLETE] Trace execution finished in ${DURATION}s."
fi

# ------------------------------------------------------------------------------
# Stage 3: Label Audit Verification
# ------------------------------------------------------------------------------
if [[ "${STAGE}" == "all" || "${STAGE}" == "audit" ]]; then
    echo ""
    echo "--- [STAGE 3: LABEL AUDIT & VERIFICATION] ---"
    mkdir -p "${REPORTS_DIR}"
    "${PYTHON_BIN}" -m target_graph.pipelines.label_audit \
        --config "${CONFIG_FILE}" \
        --cases-root "${CASES_ROOT}" \
        --output-dir "${REPORTS_DIR}"
    
    echo ""
    echo "[STAGE 3 COMPLETE] Audit report generated at ${REPORTS_DIR}/label_yield_audit.json."
fi

echo ""
echo "================================================================================"
echo " [SUCCESS] TargetGraph pipeline run_all finished successfully."
echo "================================================================================"
