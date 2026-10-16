#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON=${PYTHON:-python3}
OUT=outputs/bench_scores
mkdir -p "$OUT"
# Prevent two resumptions from writing the same model cache concurrently.
exec 9>"$OUT/resume.lock"
flock -n 9 || { echo 'Another scoring run is active.' >&2; exit 1; }
export MPLCONFIGDIR=${MPLCONFIGDIR:-/tmp/matplotlib-bench}
# Refresh CSV/progress during inference; stop the watcher on failure or completion.
"$PYTHON" bench_tools/watch_exports.py > "$OUT/export.log" 2>&1 &
WATCHER=$!
trap 'kill "$WATCHER" 2>/dev/null || true' EXIT
printf '%s\n' "Running: $(date -Is)" > "$OUT/resume_status.txt"
if "$PYTHON" -u score_bench.py --stage score --device "${DEVICE:-auto}" --local-files-only >> "$OUT/runtime.log" 2>&1; then
    "$PYTHON" score_bench.py --stage export
    # Watcher writes the final progress count before exiting.
    wait "$WATCHER"
    "$PYTHON" ../bench/linescore/prepare.py > "$OUT/linescore_export.log" 2>&1
    printf '%s\n' "Complete: $(date -Is)" > "$OUT/resume_status.txt"
else
    printf '%s\n' "Failed: $(date -Is); see runtime.log" > "$OUT/resume_status.txt"
    exit 1
fi
