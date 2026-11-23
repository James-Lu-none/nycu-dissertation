#!/usr/bin/env bash
# Run upstream DG on the ORIGINAL bitcode. Preserve source instruction IDs.
# This is an exploratory sidecar and never overwrites legacy graph artifacts.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CASE_ID=""
TARGET_INST=""
CRITERION=""
CRITERION_MODE="c"
ENTRY="main"
DG_IMAGE="${DG_IMAGE:-target-graph:dg-llvm14}"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/dg_slice.sh --case CASE_ID --target-inst LLVM_INST_ID \
    --criterion CRITERION [--criterion-mode c|sc] [--entry FUNCTION]

Use analysis_v2.cli --list-targets to select the instruction explicitly.
The DG -c/-sc criterion is potentially approximate; surviving target !=
criterion proof. This exports EXPLORATORY_ONLY sidecar artifacts.
EOF
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) [[ $# -ge 2 ]] || usage; CASE_ID="$2"; shift 2 ;;
    --target-inst) [[ $# -ge 2 ]] || usage; TARGET_INST="$2"; shift 2 ;;
    --criterion) [[ $# -ge 2 ]] || usage; CRITERION="$2"; shift 2 ;;
    --criterion-mode) [[ $# -ge 2 ]] || usage; CRITERION_MODE="$2"; shift 2 ;;
    --entry) [[ $# -ge 2 ]] || usage; ENTRY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ "$CASE_ID" =~ ^[a-zA-Z0-9_.-]+$ ]] || usage
[[ -n "$TARGET_INST" && -n "$CRITERION" && -n "$ENTRY" ]] || usage
[[ "$CRITERION_MODE" == "c" || "$CRITERION_MODE" == "sc" ]] || usage
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

CASE_DIR="$ROOT_DIR/cases/$CASE_ID"
[[ -d "$CASE_DIR" ]] || { echo "Missing case directory: $CASE_DIR" >&2; exit 1; }
shopt -s nullglob
BC_FILES=("$CASE_DIR"/*.bc)
shopt -u nullglob
if [[ ${#BC_FILES[@]} -ne 1 ]]; then
  echo "Expected exactly one original .bc in $CASE_DIR (found ${#BC_FILES[@]})." >&2
  exit 1
fi
BC_NAME="$(basename "${BC_FILES[0]}")"
OUT_DIR="$CASE_DIR/dg_backend"
mkdir -p "$OUT_DIR"
if [[ -e "$OUT_DIR/dg_slice.json" ]]; then
  echo "Refusing to overwrite $OUT_DIR/dg_slice.json; archive/remove the sidecar first." >&2
  exit 1
fi

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$ROOT_DIR:/workspace" \
  -e "TARGET_GRAPH_BUILD_ID=$CASE_ID" \
  -e "BC_NAME=$BC_NAME" \
  -e "CASE_ID=$CASE_ID" \
  -e "DG_CRITERION=$CRITERION" \
  -e "DG_CRITERION_MODE=$CRITERION_MODE" \
  -e "DG_ENTRY=$ENTRY" \
  "$DG_IMAGE" bash -c '
set -euo pipefail
case_dir="/workspace/cases/$CASE_ID"
out_dir="$case_dir/dg_backend"
plugin="/usr/local/lib/DGIdentityPass.so"
test -f "$plugin"
test -x "$(command -v llvm-slicer)"
opt -load-pass-plugin="$plugin" -passes=dg-tag \
  -o "$out_dir/tagged.bc" "$case_dir/$BC_NAME"

TARGET_GRAPH_DG_EXPORT="$out_dir/before.jsonl" \
  opt -load-pass-plugin="$plugin" -passes=dg-export -disable-output \
  "$out_dir/tagged.bc"

# DG owns the dependence graph and the slicing decision.
# Criterion matching must still be reviewed for ambiguous source locations.
llvm-slicer "-$DG_CRITERION_MODE" "$DG_CRITERION" \
  -entry "$DG_ENTRY" -statistics \
  -o "$out_dir/sliced.bc" "$out_dir/tagged.bc" \
  > "$out_dir/dg.stdout.log" 2> "$out_dir/dg.stderr.log"

test -s "$out_dir/sliced.bc"
TARGET_GRAPH_DG_EXPORT="$out_dir/after.jsonl" \
  opt -load-pass-plugin="$plugin" -passes=dg-export -disable-output \
  "$out_dir/sliced.bc"
'
export PYTHONPATH="$ROOT_DIR/src:${PYTHONPATH:-}"
PYTHON_BIN="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python3}"
if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN=python3
fi
ARGS=(
  --before "$OUT_DIR/before.jsonl"
  --after "$OUT_DIR/after.jsonl"
  --source-bc "${BC_FILES[0]}"
  --target-inst "$TARGET_INST"
  --criterion "$CRITERION"
  --criterion-mode "$CRITERION_MODE"
  --output "$OUT_DIR/dg_slice.json"
)
if [[ -f "$CASE_DIR/bb_map.jsonl" ]]; then
  ARGS+=(--bb-map "$CASE_DIR/bb_map.jsonl")
fi
if [[ -f "$CASE_DIR/analysis_v2_nodes.jsonl" ]]; then
  ARGS+=(--v2-nodes "$CASE_DIR/analysis_v2_nodes.jsonl")
fi
"$PYTHON_BIN" -m target_graph.dg.validate "${ARGS[@]}"
echo "[dg] Sidecar written: $OUT_DIR/dg_slice.json"
echo "[dg] NOT VERIFIED for training: inspect criterion, inline frames and PoC trace."
