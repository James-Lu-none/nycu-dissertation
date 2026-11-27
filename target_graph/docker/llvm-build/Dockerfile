# Dockerfile for Target-Conditioned Program Graph Toolchain
# LLVM 14 Pinned Toolchain with New-PM Pass Plugin & Trace Runtime

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LLVM_VERSION=14

# Install base utilities, compilers, CMake, and LLVM 14 toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    python3 \
    python3-pip \
    python3-dev \
    bison \
    flex \
    texinfo \
    autoconf \
    automake \
    libtool \
    nasm \
    liblzo2-dev \
    zlib1g-dev \
    libbz2-dev \
    pkg-config \
    llvm-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-dev \
    llvm-${LLVM_VERSION}-tools \
    clang-${LLVM_VERSION} \
    libclang-${LLVM_VERSION}-dev \
    lld-${LLVM_VERSION} \
    binutils-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure default alternatives to LLVM 14
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_VERSION} 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-${LLVM_VERSION} 100 && \
    update-alternatives --install /usr/bin/opt opt /usr/bin/opt-${LLVM_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-${LLVM_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-${LLVM_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer /usr/bin/llvm-symbolizer-${LLVM_VERSION} 100 && \
    pip3 install --no-cache-dir wllvm

WORKDIR /opt/target_graph

# Copy LLVM pass and trace runtime source code
COPY src/target_graph/llvm /opt/target_graph/llvm

# Build Trace Runtime library
RUN mkdir -p /opt/target_graph/build/trace_runtime && \
    cd /opt/target_graph/build/trace_runtime && \
    cmake -G Ninja /opt/target_graph/llvm/trace_runtime && \
    ninja && \
    cp libtarget_graph_trace.a /usr/local/lib/ && \
    cp libtarget_graph_trace.so /usr/local/lib/

# Build TargetGraphPass LLVM New-PM plugin
RUN mkdir -p /opt/target_graph/build/passes && \
    cd /opt/target_graph/build/passes && \
    cmake -G Ninja -DLLVM_DIR=/usr/lib/llvm-${LLVM_VERSION}/lib/cmake/llvm /opt/target_graph/llvm/passes && \
    ninja && \
    cp libTargetGraphPass.so /usr/local/lib/TargetGraphPass.so && \
    cp libTargetGraphPass.so /usr/local/lib/

WORKDIR /workspace
CMD ["/bin/bash"]

# New analysis core is isolated from the legacy TargetGraphPass pipeline.
RUN cp /opt/target_graph/build/passes/libAnalysisV2Pass.so /usr/local/lib/AnalysisV2Pass.so

# LLVM identity metadata survives (when supported by DG) for exact BB/trace mapping.
RUN cp /opt/target_graph/build/passes/libDGIdentityPass.so /usr/local/lib/DGIdentityPass.so

# Direct BB-ID trace instrumentation pass.
RUN cp /opt/target_graph/build/passes/libTraceInstrumentPass.so /usr/local/lib/TraceInstrumentPass.so
