# Optional DG analysis backend. Build target-graph:llvm14 first.
# Pin DG and LLVM versions independently of the main training environment.
FROM target-graph:llvm14

ARG DG_COMMIT=dc3615d03fedfce62f37604b45d22e31c9d7e557
RUN git clone https://github.com/mchalupa/dg.git /opt/dg && \
    git -C /opt/dg checkout --detach "$DG_COMMIT" && \
    cmake -S /opt/dg -B /opt/dg/build -G Ninja \
      -DLLVM_DIR=/usr/lib/llvm-14/lib/cmake/llvm \
      -DLLVM_LINK_DYLIB=ON -DBUILD_TESTING=OFF \
      -DENABLE_FUZZING=OFF -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /opt/dg/build -j 2 && \
    test -x /opt/dg/build/tools/llvm-slicer && \
    ln -s /opt/dg/build/tools/llvm-slicer /usr/local/bin/llvm-slicer && \
    llvm-slicer -version

LABEL org.opencontainers.image.source="https://github.com/mchalupa/dg"
LABEL org.opencontainers.image.description="LLVM14 DG static slicing backend for target_graph"
