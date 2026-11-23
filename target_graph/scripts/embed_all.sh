#!/usr/bin/env bash
# ==============================================================================
# embed_all.sh - Batch extract Qwen2.5-Coder-7B basic block embeddings for all cases.
#
# Designed to run inside GPU container (pro6000 workstation) or locally with --mock.
#
# Usage:
#   ./scripts/embed_all.sh [--model MODEL] [--layer LAYER] [--config PATH] [--mock] [--force]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODEL="Qwen/Qwen2.5-Coder-7B"
LAYER=14
CONFIG_FILE="${ROOT_DIR}/configs/projects/cases.yaml"
CACHE_DIR="${ROOT_DIR}/cache/embeddings"
CHUNK_POLICY="chunk"
MOCK_FLAG=""
FORCE=false
SPECIFIC_CASES=()

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --model MODEL         Hugging Face model name/path (default: Qwen/Qwen2.5-Coder-7B)
  --layer LAYER         Hidden state layer index to pool (default: 14)
  --config PATH         Path to cases YAML config (default: configs/projects/cases.yaml)
  --cache-dir DIR       Embedding cache directory (default: cache/embeddings)
  --chunk-policy POLICY 'chunk' or 'exclude' for functions > 8k tokens (default: chunk)
  --cases ID [ID ...]   Specific case IDs to embed
  --mock                Use deterministic mock CPU extractor (no GPU required)
  --force               Force re-extraction even if case already cached
  -h, --help            Show this help message and exit

Examples:
  # Run full extraction on pro6000 GPU workstation:
  $0

  # Mock run on CPU for verification:
  $0 --mock
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model)
            MODEL="$2"; shift 2 ;;
        --layer)
            LAYER="$2"; shift 2 ;;
        --config)
            CONFIG_FILE="$2"; shift 2 ;;
        --cache-dir)
            CACHE_DIR="$2"; shift 2 ;;
        --chunk-policy)
            CHUNK_POLICY="$2"; shift 2 ;;
        --mock)
            MOCK_FLAG="--mock"; shift ;;
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

PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

echo "================================================================================"
echo " TargetGraph Batch Embedding Extraction"
echo " Model:        ${MODEL}"
echo " Layer:        ${LAYER}"
echo " Chunk Policy: ${CHUNK_POLICY}"
echo " Cache Dir:    ${CACHE_DIR}"
echo " Mock Mode:    $([[ -n "${MOCK_FLAG}" ]] && echo 'true' || echo 'false (CUDA Real)')"
echo " Force Rerun:  ${FORCE}"
echo " Config:       ${CONFIG_FILE}"
echo "================================================================================"

mkdir -p "${CACHE_DIR}"

if [[ ${#SPECIFIC_CASES[@]} -gt 0 ]]; then
    CASE_LIST=("${SPECIFIC_CASES[@]}")
else
    CASE_LIST=($("${PYTHON_BIN}" -c "
import yaml
with open('${CONFIG_FILE}', 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)
cases = [c['case_id'] for c in data.get('cases', [])]
print(' '.join(cases))
"))
fi

TOTAL=${#CASE_LIST[@]}
echo "[INFO] Loaded ${TOTAL} cases to process."

PROCESSED=0
SKIPPED=0
FAILED=0
START_TIME=$(date +%s)

for idx in "${!CASE_LIST[@]}"; do
    case_id="${CASE_LIST[$idx]}"
    count=$((idx + 1))
    
    # Check cache existence
    model_tag="${MODEL//\//-}"
    cache_subdir="${CACHE_DIR}/${case_id}"
    cache_marker="${cache_subdir}/qwen_l${LAYER}.pt"
    legacy_file="${CACHE_DIR}/${case_id}_${model_tag}_L${LAYER}.pt"

    if [[ "${FORCE}" != "true" && ( -f "${cache_marker}" || -f "${legacy_file}" || -d "${cache_subdir}" ) ]]; then
        # Check if dir has non-zero files
        if [[ -d "${cache_subdir}" && "$(find "${cache_subdir}" -maxdepth 1 -name '*.pt' 2>/dev/null | wc -l)" -gt 0 ]] || [[ -f "${legacy_file}" ]]; then
            echo "[${count}/${TOTAL}] [CACHED] ${case_id}"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi
    fi

    echo -n "[${count}/${TOTAL}] [RUNNING] ${case_id} ... "
    CMD_ARGS=(
        --case "${case_id}"
        --model "${MODEL}"
        --layer "${LAYER}"
        --cache-dir "${CACHE_DIR}"
        --chunk-policy "${CHUNK_POLICY}"
    )
    if [[ -n "${MOCK_FLAG}" ]]; then
        CMD_ARGS+=("${MOCK_FLAG}")
    fi

    if "${PYTHON_BIN}" -m target_graph.embeddings.qwen_cli "${CMD_ARGS[@]}" > /dev/null 2>&1; then
        echo "SUCCESS"
        PROCESSED=$((PROCESSED + 1))
    else
        echo "FAILED" >&2
        FAILED=$((FAILED + 1))
    fi
done

ELAPSED=$(( $(date +%s) - START_TIME ))

echo ""
echo "================================================================================"
echo " Batch Embedding Extraction Complete"
echo " Total Cases:  ${TOTAL}"
echo " Processed:    ${PROCESSED}"
echo " Skipped:      ${SKIPPED}"
echo " Failed:       ${FAILED}"
echo " Elapsed Time: ${ELAPSED}s"
echo " Cache Dir:    ${CACHE_DIR}"
echo "================================================================================"

if [[ ${FAILED} -gt 0 ]]; then
    exit 1
fi
