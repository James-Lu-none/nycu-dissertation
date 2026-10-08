#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# Activate your conda environment before running this script.
# On Slurm, request --cpus-per-task=24 for 24 CPU workers.
cpu_jobs="${CPU_JOBS:-24}"
review_batch_size="${REVIEW_BATCH_SIZE:-8}"
dataset="dataset/review/dataset.jsonl"
export HF_HOME="${HF_HOME:-/raid/khyeh/hf_cache}"
export HF_HUB_CACHE="${HF_HUB_CACHE:-$HF_HOME/hub}"

mkdir -p outputs
pipeline_dir=$(mktemp -d "outputs/pipeline_$(TZ=Asia/Taipei date +%Y%m%d_%H%M%S)_XXXXXX")
printf 'Pipeline output: %s\n' "$pipeline_dir"

# Reuse dataset/review/dataset.jsonl if present; otherwise review all sources.
# To review again: python review_dataset.py --batch-size 8 --force-review
python review_dataset.py --batch-size "$review_batch_size"

# Run ALL and each CWE for ModernBERT and SecureBERT2 (neuron + function probe).
# Neuron reuses matching training summaries in dataset/activation_cache/.
# C/D/E fits share the CPU job queue; validation/test activations are not cached.
# Each neuron run saves models.joblib, inference_models.joblib, and reports.
# E region diagnostics: rbf_region_report.csv + rbf_region_histograms/layer_*.png.
# Histograms show tanh(margin); AUROC uses raw margins. No delta clustering plot.
python run_cwe_experiments.py --dataset "$dataset" \
  --cwe-source dataset/source/*.jsonl \
  --cpu-jobs "$cpu_jobs" \
  --output-dir "$pipeline_dir/experiments"

# Optional standalone stages (use the same model, CWE, and split settings).
# python extract_representations.py --dataset "$dataset" --model modernbert
# python train_methods.py --dataset "$dataset" --model modernbert --cpu-jobs "$cpu_jobs" --top-k-ratio 0.1
# python evaluate_models.py --dataset "$dataset" --model modernbert --models /path/to/models.joblib
# python inference.py --models /path/to/inference_models.joblib --code example.c --output scores.json
# Extraction: --refresh-cache rebuilds summaries. Training: --top-k-ratio 1 selects all neurons.
