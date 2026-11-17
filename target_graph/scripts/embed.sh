#!/usr/bin/env bash
# Standalone Qwen2.5-Coder-7B embedding extraction script.
# Run on GPU cluster node or locally with --mock.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CASE_ID=""
MODEL="Qwen/Qwen2.5-Coder-7B"
LAYER=14
CACHE_DIR="${ROOT_DIR}/cache/embeddings"
CHUNK_POLICY="chunk"
MOCK_FLAG=""

usage() {
    echo "Usage: $0 --case CASE_ID [--model MODEL] [--layer LAYER] [--cache-dir DIR] [--chunk-policy chunk|exclude] [--mock]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)
            CASE_ID="$2"; shift 2 ;;
        --model)
            MODEL="$2"; shift 2 ;;
        --layer)
            LAYER="$2"; shift 2 ;;
        --cache-dir)
            CACHE_DIR="$2"; shift 2 ;;
        --chunk-policy)
            CHUNK_POLICY="$2"; shift 2 ;;
        --mock)
            MOCK_FLAG="--mock"; shift ;;
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

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

"${PYTHON_BIN}" -m target_graph.embeddings.qwen_cli \
    --case "${CASE_ID}" \
    --model "${MODEL}" \
    --layer "${LAYER}" \
    --cache-dir "${CACHE_DIR}" \
    --chunk-policy "${CHUNK_POLICY}" \
    ${MOCK_FLAG}

echo "[SUCCESS] Embeddings extracted and cached for case: ${CASE_ID} (layer ${LAYER})"
