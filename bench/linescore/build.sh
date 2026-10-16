#!/usr/bin/env bash
set -euo pipefail
# Usage: bash linescore/build.sh BENCHMARK [IMAGE_TAG]
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
BENCHMARK=${1:?Specify a benchmark directory name}
TAG=${2:-"linescore:${BENCHMARK,,}"}
# Refuse incomplete inference results; never silently build a baseline-only comparison.
python3 "$ROOT/linescore/prepare.py" --benchmark "$BENCHMARK"
docker build -f "$ROOT/$BENCHMARK/Dockerfile.linescore" -t "$TAG" "$ROOT/$BENCHMARK"
