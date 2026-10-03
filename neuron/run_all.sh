#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# Activate the environment before running: conda activate /raid/khyeh/miniconda_envs/vul-neuron
export HF_HOME="${HF_HOME:-/raid/khyeh/hf_cache}"
export HF_HUB_CACHE="${HF_HUB_CACHE:-$HF_HOME/hub}"
mkdir -p outputs
pipeline_dir=$(mktemp -d "outputs/pipeline_$(TZ=Asia/Taipei date +%Y%m%d_%H%M%S)_XXXXXX")
printf 'Pipeline output: %s\n' "$pipeline_dir"

for source in bigvul cvefixes; do
  python review_dataset.py --input "dataset/source/$source.jsonl" \
    --output-dir "$pipeline_dir/$source" --batch-size 8
done

# Each source has exactly one run in this newly created pipeline directory.
kept=( "$pipeline_dir"/bigvul/*/kept.jsonl "$pipeline_dir"/cvefixes/*/kept.jsonl )
for path in "${kept[@]}"; do
  test -f "$path"
done

python run_cwe_experiments.py --dataset "${kept[@]}" \
  --cwe-source dataset/source/bigvul.jsonl dataset/source/cvefixes.jsonl \
  --output-dir "$pipeline_dir/experiments"
