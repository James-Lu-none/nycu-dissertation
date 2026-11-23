# GPU-accelerated Docker environment for TargetGraph Embedding Extraction & GNN Training
# Designed for workstation deployment (NVIDIA RTX 6000 / CUDA 12.8+)
FROM nvidia/cuda:12.8.1-cudnn-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

# Install core build and debugging utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        git \
        ca-certificates \
        curl \
        nvtop \
        htop \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# Symlink python -> python3
RUN ln -sf /usr/bin/python3 /usr/local/bin/python

# Upgrade pip
RUN python3 -m pip install --upgrade pip setuptools wheel

# Install PyTorch with CUDA 12 support
RUN python3 -m pip install \
    torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Install Hugging Face, LLM, and Graph Neural Network packages
RUN python3 -m pip install \
    transformers>=4.45.0 \
    accelerate>=0.30.0 \
    tokenizers \
    sentencepiece \
    tiktoken \
    torch-geometric \
    pandas \
    pyarrow \
    scipy \
    networkx \
    tqdm \
    pyyaml \
    ruamel.yaml \
    pytest

WORKDIR /workspace/nycu-dissertation/target_graph

ENV PYTHONPATH="/workspace/nycu-dissertation/target_graph/src:${PYTHONPATH:-}"

CMD ["sleep", "infinity"]
