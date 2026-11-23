#!/usr/bin/env bash
# ==============================================================================
# pack_artifacts.sh - Pack lightweight, self-contained artifacts for GPU server.
#
# Strips ~55GB of redundant compiler intermediate files (*.jsonl, binaries, .bc)
# while preserving all Parquet graphs, source code, dependency slices, traces,
# and configurations required for Qwen2.5 Embedding extraction and GNN training.
#
# Usage:
#   ./scripts/pack_artifacts.sh [--output PATH]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_FILE="${ROOT_DIR}/target_graph_artifacts.tar.gz"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o)
            OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--output PATH]"
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1 ;;
    esac
done

echo "================================================================================"
echo " Packaging TargetGraph Core Artifacts for Remote Workstation"
echo " Target output: ${OUTPUT_FILE}"
echo " Root dir:      ${ROOT_DIR}"
echo "================================================================================"

cd "${ROOT_DIR}"

# Build list of essential files
echo "[1/3] Building manifest of training & embedding artifacts..."
MANIFEST=$(mktemp)

# Include core code, configs, reports, docker configurations
find configs docker reports scripts src pyproject.toml docker-compose.gpu.yml -type f >> "${MANIFEST}" 2>/dev/null || true

# Include essential case artifacts: parquet, src, slices, traces, pocs
find cases -type f \( \
    -path '*/parquet/*' -o \
    -path '*/src/*' -o \
    -name 'dep_slice.json' -o \
    -name 'trace_crash.txt' -o \
    -name 'crash_stderr.txt' -o \
    -name 'coverage.json' -o \
    -name 'pass_summary.json' -o \
    -name 'poc' -o \
    -name 'poc.*' \
\) >> "${MANIFEST}"

TOTAL_FILES=$(wc -l < "${MANIFEST}")
echo "[INFO] Collected ${TOTAL_FILES} essential artifact files across 300 cases."

echo "[2/3] Compressing into ${OUTPUT_FILE} (this may take 1-2 minutes)..."
tar -czf "${OUTPUT_FILE}" -T "${MANIFEST}"
rm -f "${MANIFEST}"

ARCHIVE_SIZE=$(du -h "${OUTPUT_FILE}" | cut -f1)
echo "[3/3] Compression complete!"
echo "================================================================================"
echo " [SUCCESS] Artifact package created: ${OUTPUT_FILE}"
echo " Total archive size: ${ARCHIVE_SIZE}"
echo "================================================================================"
echo "To transfer to remote workstation (pro6000):"
echo "  scp ${OUTPUT_FILE} user@pro6000:/workspace/"
echo "On pro6000 workstation:"
echo "  tar -xzf target_graph_artifacts.tar.gz"
echo "  docker compose -f docker-compose.gpu.yml up -d"
echo "  docker exec -it target-graph-gpu ./scripts/embed_all.sh"
echo "================================================================================"
