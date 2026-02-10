FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# 基本工具
RUN apt update && apt install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    python3 \
    python3-pip \
    curl \
    ca-certificates \
    libboost-all-dev \
    libssl-dev \
    zlib1g-dev \
    pkg-config

# LLVM 12
RUN apt install -y \
    clang-12 \
    llvm-12 \
    llvm-12-dev

# Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# 預設 toolchain
ENV CC=clang-12
ENV CXX=clang++-12
ENV LLVM_CONFIG=llvm-config-12

WORKDIR /workspace
