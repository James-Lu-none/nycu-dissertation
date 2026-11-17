#!/usr/bin/env bash
# Fetch / verify cases from manifest.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MANIFEST="${ROOT_DIR}/configs/projects/cases.yaml"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest)
            MANIFEST="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--manifest configs/projects/cases.yaml]"
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1 ;;
    esac
done

echo "[FETCH] Validating manifest at ${MANIFEST}..."
if [[ ! -f "${MANIFEST}" ]]; then
    echo "Error: Manifest ${MANIFEST} not found." >&2
    exit 1
fi

PYTHON_BIN="${VIRTUAL_ENV:-/home/user/workspace/.venv}/bin/python3"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="python3"
fi

"${PYTHON_BIN}" -c "
import yaml
from pathlib import Path

with open('${MANIFEST}') as f:
    cfg = yaml.safe_load(f)

cases = cfg.get('cases', [])
print(f'Total configured benchmark cases: {len(cases)}')
for c in cases:
    cid = c['case_id']
    poc = Path(c['poc_path'])
    status = 'EXISTS' if poc.exists() else 'MISSING'
    print(f'  - {cid}: PoC [{status}] -> {poc}')
"
echo "[FETCH] Case verification complete."

