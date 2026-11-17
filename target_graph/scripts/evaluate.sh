#!/usr/bin/env bash
# Evaluation and AFLGo distance scaling script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONFIG="${ROOT_DIR}/configs/train/rgcn.yaml"
CHECKPOINT="${ROOT_DIR}/checkpoints/rgcn/rgcn_ranker_final.pt"
ETA=1.0
OUTPUT_DIR="${ROOT_DIR}/reports"

usage() {
    echo "Usage: $0 [--config PATH] [--checkpoint PATH] [--eta FLOAT] [--output-dir DIR]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG="$2"; shift 2 ;;
        --checkpoint)
            CHECKPOINT="$2"; shift 2 ;;
        --eta)
            ETA="$2"; shift 2 ;;
        --output-dir)
            OUTPUT_DIR="$2"; shift 2 ;;
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

"${PYTHON_BIN}" -m target_graph.analysis.evaluate_cli \
    --config "${CONFIG}" \
    --checkpoint "${CHECKPOINT}" \
    --eta "${ETA}" \
    --output-dir "${OUTPUT_DIR}"

