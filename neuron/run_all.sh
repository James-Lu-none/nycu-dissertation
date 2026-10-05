#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# Activate the environment before running: conda activate /raid/khyeh/miniconda_envs/vul-neuron
export HF_HOME="${HF_HOME:-/raid/khyeh/hf_cache}"
export HF_HUB_CACHE="${HF_HUB_CACHE:-$HF_HOME/hub}"
mkdir -p outputs
pipeline_dir=$(mktemp -d "outputs/pipeline_$(TZ=Asia/Taipei date +%Y%m%d_%H%M%S)_XXXXXX")
printf 'Pipeline output: %s\n' "$pipeline_dir"

python review_dataset.py --batch-size 8

python run_cwe_experiments.py --dataset dataset/review/dataset.jsonl \
  --cwe-source dataset/source/*.jsonl \
  --output-dir "$pipeline_dir/experiments"
