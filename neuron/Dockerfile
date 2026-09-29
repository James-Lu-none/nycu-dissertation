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
    python3 -m pip install -r /tmp/requirements.txt

WORKDIR /workspace

CMD ["python3", "stt.py"]