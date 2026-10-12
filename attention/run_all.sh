#!/usr/bin/env bash
set -euo pipefail
# Reuse the neuron environment (Transformers 4.57.x); pip install -r requirements.txt
cd "$(dirname "$0")"

# Reuse reviewed pairs. Keep the existing ALL split when the reference is available.
dataset=${DATASET:-../neuron/dataset/review/dataset.jsonl}
reference=${REFERENCE_MODELS:-../neuron/outputs/neuron_modernbert_20261010_131817_570904/inference_models.joblib}
models=${MODELS:-modernbert}
modes=${MODES:-classification rationale random hidden}
root=${OUTPUT_DIR:-outputs/pipeline_$(TZ=Asia/Taipei date +%Y%m%d_%H%M%S)}
mkdir -p "$root"

# ModernBERT/SecureBERT2: 8192; CodeBERT: 512. Exclude whole pairs; never truncate.
# Set MODELS="codebert modernbert securebert2" to run every encoder.
# MAX_LENGTH=512 applies the same token budget (tokenizers still differ).
# All arms fine-tune the full encoder; same initialization, split, and training budget.
# MODES="rationale hidden" runs only the two supervised localization arms.
# Hidden: final token hidden states -> line mean -> linear head -> line softmax.
# Stop after PATIENCE epochs without >MIN_DELTA improvement; 0 disables stopping.
# Save every strict best validation score even if its improvement is <MIN_DELTA.
# Select checkpoints by validation MRR. Test labels never select epochs or loss weights.
# CLS scores use the last global layer, not the old all-layer incoming-attention score.
# Random targets match the number of proxy lines, not their token lengths.
# Loss: function CE + 0.1 * train-calibrated balance * uniform-positive-line CE.
# Model-specific length filtering can change cohorts; consult data_counts.csv.
# Two independent GPU workers; inherited Slurm CUDA_VISIBLE_DEVICES is respected.
# GPU_IDS="0,1" overrides IDs; MODELS/MODES choose the queued experiments.
# Training progress stays in each experiment's .log; terminal shows job status.
extra=()
if [[ -n "${GPU_IDS:-}" ]]; then extra+=(--gpus "$GPU_IDS"); fi
if [[ -n "${MAX_LENGTH:-}" ]]; then extra+=(--max-length "$MAX_LENGTH"); fi
python -u run_parallel.py --models $models --modes $modes \
  --output-root "$root" "${extra[@]}" \
  --dataset "$dataset" --reference-models "$reference" \
  --epochs "${EPOCHS:-100}" --batch-size "${BATCH_SIZE:-1}" \
  --patience "${PATIENCE:-5}" --min-delta "${MIN_DELTA:-0.001}" \
  --accumulation "${ACCUMULATION:-16}" --lr "${LR:-2e-5}" \
  --cpu-threads "${CPU_THREADS:-4}" \
  --attention-weight "${ATTENTION_WEIGHT:-0.1}" --seed "${SEED:-42}"
