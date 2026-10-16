#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python}"
# Download each distinct benchmark source/setup once under workspace/temp.
"$PYTHON" bench_tools/prepare_sources.py
# Index the entire source trees; score complete functions listed by the slices.
# Set SCOPE=all to also score every other successfully parsed function.
"$PYTHON" score_bench.py --stage all --scope "${SCOPE:-slice}" \
  --device "${DEVICE:-auto}" --cpu-threads "${CPU_THREADS:-4}" "$@"
# Repeat scoring with --stage score, then --stage export, to reuse the saved index.
