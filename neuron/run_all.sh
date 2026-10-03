# srun -w dgx-cn02 --pty --time=24:00:00 --gpus=1 /bin/bash

conda activate /raid/khyeh/miniconda_envs/vul-neuron

export HF_HOME=/raid/khyeh/hf_cache
export HF_HUB_CACHE=/raid/khyeh/hf_cache/hub

python review_dataset.py \
  --input dataset/source/bigvul.jsonl \
  --output dataset/audits/bigvul_v5.jsonl \
  --batch-size 1
python review_dataset.py \
  --input dataset/source/cvefixes.jsonl \
  --output dataset/audits/cvefixes_v5.jsonl \
  --batch-size 1

python neuron.py \
  --model modernbert \
  --dataset dataset/source/bigvul.jsonl dataset/source/cvefixes.jsonl \
  --cwe CWE-119
python neuron.py \
  --model securebert2 \
  --dataset dataset/source/bigvul.jsonl dataset/source/cvefixes.jsonl \
  --cwe CWE-119

python function_probe.py \
  --model modernbert \
  --dataset dataset/source/bigvul.jsonl dataset/source/cvefixes.jsonl \
  --max-length 8192 \
  --cwe CWE-119
python function_probe.py \
  --model securebert2 \
  --dataset dataset/source/bigvul.jsonl dataset/source/cvefixes.jsonl \
  --max-length 8192 \
  --cwe CWE-119