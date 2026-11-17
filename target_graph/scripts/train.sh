#!/usr/bin/env bash
# Training script for Target-Conditioned R-GCN Ranker.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONFIG="${ROOT_DIR}/configs/train/rgcn.yaml"
EPOCHS=""
CASES=""

usage() {
    echo "Usage: $0 [--config PATH] [--epochs NUM] [--cases CASE1 CASE2 ...]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG="$2"; shift 2 ;;
        --epochs)
            EPOCHS="$2"; shift 2 ;;
        --cases)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                CASES="${CASES} $1"
                shift
            done
            ;;
        -h|--help)
            usage ;;
        *)
            echo "Unknown argument: $1" >&2
            usage ;;
    esac
done

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

ARGS=(--config "${CONFIG}")
if [[ -n "${EPOCHS}" ]]; then
    ARGS+=(--epochs "${EPOCHS}")
fi
if [[ -n "${CASES}" ]]; then
    ARGS+=(--cases ${CASES})
fi

"${PYTHON_BIN}" -m target_graph.training.train_cli "${ARGS[@]}"
