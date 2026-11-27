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

# An alias case must reuse the canonical BuildID and ModuleName of the graph.
CANONICAL_RECORD="$(PYTHONPATH="$ROOT_DIR/src:${PYTHONPATH:-}" python3 \
  -m target_graph.svf.provenance \
  --pass-summary "$CASE_DIR/pass_summary.json" \
  --bitcode-name "$BC_NAME")"
mapfile -t ID_FIELDS <<< "$CANONICAL_RECORD"
if [[ ${#ID_FIELDS[@]} -ne 2 || -z "${ID_FIELDS[0]}" || -z "${ID_FIELDS[1]}" ]]; then
  echo "Missing canonical graph identity provenance" >&2
  exit 1
fi

docker run --rm \
  -v "$ROOT_DIR:/workspace" \
  -e "TARGET_GRAPH_BUILD_ID=${ID_FIELDS[0]}" \
  -e "TARGET_GRAPH_ID_MODULE_NAME=${ID_FIELDS[1]}" \
  -e "CASE_ID=$CASE_ID" \
  -e "TARGET_GRAPH_OUT_DIR=/workspace/cases/$CASE_ID" \
  -e "ANALYSIS_V2_BC_NAME=$BC_NAME" \
  target-graph:llvm14 bash -c '
set -euo pipefail
PLUGIN=/usr/local/lib/AnalysisV2Pass.so
test -f "$PLUGIN"
sha256sum "$PLUGIN"
opt -load-pass-plugin="$PLUGIN" -passes=analysis-v2 -disable-output \
  "/workspace/cases/$CASE_ID/$ANALYSIS_V2_BC_NAME"
'
echo "[analysis-v2] Artifacts for $CASE_ID:"
ls -lh "$CASE_DIR"/analysis_v2_*
