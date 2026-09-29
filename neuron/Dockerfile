FROM nvidia/cuda:12.8.1-cudnn-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

# Python + ffmpeg
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        ffmpeg \
        ca-certificates \
        nvtop && \
    rm -rf /var/lib/apt/lists/*

# Make `python` available too
RUN ln -sf /usr/bin/python3 /usr/local/bin/python

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install -r /tmp/requirements.txt && \
    python3 -m pip check && \
    python3 -c 'import torch; from importlib.metadata import version; assert torch.version.cuda == "12.8", torch.version.cuda; assert version("vllm") == "0.12.0"; print("PyTorch:", torch.__version__, "CUDA:", torch.version.cuda, "vLLM:", version("vllm"))'

WORKDIR /workspace

CMD ["python3", "stt.py"]
