#!/usr/bin/env bash
set -euo pipefail
# Reuse the neuron environment (Transformers 4.57.x); pip install -r requirements.txt
cd "$(dirname "$0")"

# Reuse reviewed pairs. Keep the existing ALL split when the reference is available.
dataset=${DATASET:-../neuron/dataset/review/dataset.jsonl}
reference=${REFERENCE_MODELS:-../neuron/outputs/neuron_modernbert_20261010_131817_570904/inference_models.joblib}
models=${MODELS:-modernbert}
root=${OUTPUT_DIR:-outputs/pipeline_$(TZ=Asia/Taipei date +%Y%m%d_%H%M%S)}
mkdir -p "$root"

# ModernBERT/SecureBERT2: 8192; CodeBERT: 512. Exclude whole pairs; never truncate.
# Set MODELS="codebert modernbert securebert2" to run every encoder.
# MAX_LENGTH=512 applies the same token budget (tokenizers still differ).
# All arms fine-tune the full encoder; same initialization, split, and training budget.
# Select checkpoints by validation MRR. Test labels never select epochs or loss weights.
# CLS scores use the last global layer, not the old all-layer incoming-attention score.
# Random targets match the number of proxy lines, not their token lengths.
# Loss: function CE + 0.1 * train-calibrated balance * uniform-positive-line CE.
# Model-specific length filtering can change cohorts; consult data_counts.csv.
for model in $models; do
  limit=8192
  if [[ "$model" == codebert ]]; then limit=512; fi
  for mode in classification rationale random; do
    dest="$root/${model}_${mode}"
    python -u train.py --dataset "$dataset" --reference-models "$reference" \
      --model "$model" --mode "$mode" --max-length "${MAX_LENGTH:-$limit}" \
      --epochs "${EPOCHS:-3}" --batch-size "${BATCH_SIZE:-1}" \
      --accumulation "${ACCUMULATION:-16}" --lr "${LR:-2e-5}" \
      --attention-weight "${ATTENTION_WEIGHT:-0.1}" --seed "${SEED:-42}" \
      --output-dir "$dest" 2>&1 | tee "$root/${model}_${mode}.log"
  done
done
python summarize.py "$root"
