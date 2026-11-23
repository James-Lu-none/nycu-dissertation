#!/usr/bin/env bash
# Extract independent instruction-level graph without modifying legacy Parquet.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "$#" -ne 2 || "$1" != "--case" || -z "$2" ]]; then
  echo "Usage: $0 --case CASE_ID" >&2
  exit 2
fi
CASE_ID="$2"
if [[ ! "$CASE_ID" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
  echo "Invalid case identifier." >&2
  exit 2
fi

CASE_DIR="$ROOT_DIR/cases/$CASE_ID"
if [[ ! -d "$CASE_DIR" ]]; then
  echo "Missing case $CASE_DIR. Use the existing benchmark build pipeline." >&2
  exit 1
fi
BC_PATH="$(find "$CASE_DIR" -maxdepth 1 -name '*.bc' -type f -print -quit)"
if [[ -z "$BC_PATH" ]]; then
  echo "Missing LLVM bitcode (.bc) for $CASE_ID." >&2
  exit 1
fi
BC_NAME="$(basename "$BC_PATH")"

docker run --rm \
  -v "$ROOT_DIR:/workspace" \
  -e "TARGET_GRAPH_BUILD_ID=$CASE_ID" \
  -e "TARGET_GRAPH_OUT_DIR=/workspace/cases/$CASE_ID" \
  -e "ANALYSIS_V2_BC_NAME=$BC_NAME" \
  target-graph:llvm14 bash -c '
set -euo pipefail
PLUGIN=/usr/local/lib/AnalysisV2Pass.so
test -f "$PLUGIN"
sha256sum "$PLUGIN"
opt -load-pass-plugin="$PLUGIN" -passes=analysis-v2 -disable-output \
  "/workspace/cases/$TARGET_GRAPH_BUILD_ID/$ANALYSIS_V2_BC_NAME"
'
echo "[analysis-v2] Artifacts for $CASE_ID:"
ls -lh "$CASE_DIR"/analysis_v2_*
