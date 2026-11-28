#!/usr/bin/env bash
# Pin SVF-2.9/LLVM14, tag original LLVM instructions, run real SVFG value-flow
# analysis with a strict runtime budget and fail-closed identity checks.
# Existing graph, DG, PoC trace and model data remain unchanged.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CASE_ID=""
TARGET_INST=""
MAX_NODES=100000
MAX_EDGES=300000
TIMEOUT_SEC=120
SVF_IMAGE="${SVF_IMAGE:-target-graph:svf-llvm14}"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/svf_slice.sh --case CASE_ID --target-inst ORIGINAL_BB:INSTR_ORD \
    [--timeout-sec 120] [--max-nodes 100000] [--max-edges 300000]

This runs Andersen + SVFG construction then BACKWARD VALUE-FLOW ONLY.
It is NOT a complete SDG/CDG slicer or verified vulnerability label.
Use analysis_v2.cli --list-targets to manually inspect candidate fault sites.
EOF
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) [[ $# -ge 2 ]] || usage; CASE_ID="$2"; shift 2 ;;
    --target-inst) [[ $# -ge 2 ]] || usage; TARGET_INST="$2"; shift 2 ;;
    --timeout-sec) [[ $# -ge 2 ]] || usage; TIMEOUT_SEC="$2"; shift 2 ;;
    --max-nodes) [[ $# -ge 2 ]] || usage; MAX_NODES="$2"; shift 2 ;;
    --max-edges) [[ $# -ge 2 ]] || usage; MAX_EDGES="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ "$CASE_ID" =~ ^[A-Za-z0-9_.-]+$ ]] || usage
[[ -n "$TARGET_INST" ]] || usage
for limit in "$TIMEOUT_SEC" "$MAX_NODES" "$MAX_EDGES"; do
  [[ "$limit" =~ ^[0-9]+$ && "$limit" != 0 ]] || usage
done
command -v docker >/dev/null || { echo "Missing docker" >&2; exit 1; }

CASE_DIR="$ROOT_DIR/cases/$CASE_ID"
[[ -d "$CASE_DIR" ]] || { echo "No case directory: $CASE_DIR" >&2; exit 1; }
shopt -s nullglob
BC_FILES=("$CASE_DIR"/*.bc)
shopt -u nullglob
if [[ ${#BC_FILES[@]} -ne 1 ]]; then
  echo "Expected exactly one original .bc in $CASE_DIR; found ${#BC_FILES[@]}" >&2
  exit 1
fi
BC_NAME="$(basename "${BC_FILES[0]}")"
export PYTHONPATH="$ROOT_DIR/src:${PYTHONPATH:-}"
PYTHON_BIN="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python3}"
if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then PYTHON_BIN=python3; fi

OUT_DIR="$CASE_DIR/svf_backend"
mkdir -p "$OUT_DIR"
if [[ -e "$OUT_DIR/svf_slice.json" ]]; then
  echo "Refusing to overwrite existing $OUT_DIR/svf_slice.json" >&2
  exit 1
fi

# Step 1: verify pre-exported instruction map from bb-tag exists.
INST_MAP="$CASE_DIR/inst_map.jsonl"
if [[ ! -s "$INST_MAP" ]]; then
  echo "Missing inst_map.jsonl in $CASE_DIR (rebuild with bb-tag)" >&2
  exit 1
fi

CHECK_ARGS=(--before "$INST_MAP" --target-inst "$TARGET_INST")
if [[ -f "$CASE_DIR/bb_map.jsonl" ]]; then
  CHECK_ARGS+=(--bb-map "$CASE_DIR/bb_map.jsonl")
fi
if [[ -f "$CASE_DIR/analysis_v2_nodes.jsonl" ]]; then
  CHECK_ARGS+=(--v2-nodes "$CASE_DIR/analysis_v2_nodes.jsonl")
fi

# Step 2: preflight BEFORE Andersen, avoiding expensive work on stale targets.
"$PYTHON_BIN" -m target_graph.svf.validate preflight "${CHECK_ARGS[@]}"

# Step 3: a budgeted real SVFG analysis, not a graphviz/dot approximation.
# No partial result is promoted if process times out or crashes.
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$ROOT_DIR:/workspace" \
  -e "CASE_ID=$CASE_ID" -e "BC_NAME=$BC_NAME" -e "TARGET_INST=$TARGET_INST" \
  -e "MAX_NODES=$MAX_NODES" -e "MAX_EDGES=$MAX_EDGES" \
  -e "SVF_TIMEOUT_SEC=$TIMEOUT_SEC" \
  "$SVF_IMAGE" bash -c '
set -euo pipefail
out="/workspace/cases/$CASE_ID/svf_backend"
bc="/workspace/cases/$CASE_ID/$BC_NAME"
rm -f "$out/svfg_raw.tmp.json"
cd "$out"
timeout --signal=TERM --kill-after=10s "$SVF_TIMEOUT_SEC" \
  targetgraph-svf \
    --input "$bc" \
    --extapi-bc "/opt/SVF/Release-build/svf-llvm/extapi.bc" \
    --target-inst "$TARGET_INST" \
    --max-nodes "$MAX_NODES" \
    --max-edges "$MAX_EDGES" \
    --output "$out/svfg_raw.tmp.json" \
  > "$out/svf.stdout.log" 2> "$out/svf.stderr.log"
test -s "$out/svfg_raw.tmp.json"
mv "$out/svfg_raw.tmp.json" "$out/svfg_raw.json"
'

# Step 4: verify SVF nodes/edges against original bitcode identities.
"$PYTHON_BIN" -m target_graph.svf.validate finish \
  "${CHECK_ARGS[@]}" \
  --raw "$OUT_DIR/svfg_raw.json" \
  --source-bc "${BC_FILES[0]}" \
  --output "$OUT_DIR/svf_slice.json"
echo "[svf] Wrote $OUT_DIR/svf_slice.json (EXPLORATORY_ONLY)"
