# Real SVF-2.9/LLVM14 backend. Build target-graph:llvm14 first.
# SVF-2.9 release officially targets LLVM 14, unlike current SVF master.
FROM target-graph:llvm14

ARG SVF_COMMIT=0e56bc038bf207a1ca320b5f5ad241e13ab33e14
RUN apt-get update && apt-get install -y --no-install-recommends \
    libz3-dev libncurses-dev && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir cmake

RUN git clone https://github.com/SVF-tools/SVF.git /opt/SVF && \
    git -C /opt/SVF checkout --detach "$SVF_COMMIT" && \
    test "$(git -C /opt/SVF rev-parse HEAD)" = "$SVF_COMMIT"

# Create a separate CMake directory because add_llvm_executable checks for
# unlisted source files in sibling targets' directories.
RUN mkdir -p /opt/SVF/svf-llvm/tools/TargetGraph
COPY src/target_graph/svf/svf_target_slice.cpp \
     /opt/SVF/svf-llvm/tools/TargetGraph/targetgraph-svf.cpp
RUN printf 'add_llvm_executable(targetgraph-svf targetgraph-svf.cpp)\ntarget_link_libraries(targetgraph-svf PUBLIC ${llvm_libs} SvfLLVM)\nset_target_properties(targetgraph-svf PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)\n' \
      > /opt/SVF/svf-llvm/tools/TargetGraph/CMakeLists.txt && \
    printf '\nadd_subdirectory(TargetGraph)\n' \
      >> /opt/SVF/svf-llvm/tools/CMakeLists.txt

RUN cmake -S /opt/SVF -B /opt/SVF/Release-build -G Ninja \
      -DLLVM_DIR=/usr/lib/llvm-14/lib/cmake/llvm \
      -DZ3_DIR=/usr \
      -DCMAKE_BUILD_TYPE=Release \
      -DSVF_WARN_AS_ERROR=OFF \
      -DSVF_ENABLE_ASSERTIONS=ON && \
    cmake --build /opt/SVF/Release-build --target gen_extapi_ir targetgraph-svf -j 2 && \
    test -x /opt/SVF/Release-build/bin/targetgraph-svf && \
    test -s /opt/SVF/Release-build/svf-llvm/extapi.bc && \
    ln -s /opt/SVF/Release-build/bin/targetgraph-svf \
          /usr/local/bin/targetgraph-svf

LABEL org.opencontainers.image.source="https://github.com/SVF-tools/SVF"
LABEL org.opencontainers.image.description="Pinned SVF-2.9/LLVM14 target-site SVFG adapter"
