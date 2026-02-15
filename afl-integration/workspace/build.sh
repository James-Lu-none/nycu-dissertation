# export LLVM_CONFIG=llvm-config-15  # 視版本而定
# export CC=afl-clang-lto
# export CXX=afl-clang-lto++
# make clean && make
# 如果專案是用 CMake
# cmake -DCMAKE_C_COMPILER=afl-clang-lto -DCMAKE_CXX_COMPILER=afl-clang-lto++ .
# make

# 這邊使用 afl-clang-lto (Link Time Optimization)，因為afl-clang-fast

# 1. 編譯普通版本 (用於速度)
afl-clang-lto target.c -o target_normal

# 2. 編譯 ASAN 版本
export AFL_USE_ASAN=1
afl-clang-lto target.c -o target_asan
unset AFL_USE_ASAN

# 3. 編譯 MSAN 版本
export AFL_USE_MSAN=1
afl-clang-lto target.c -o target_msan
unset AFL_USE_MSAN

# 4. 編譯 UBSAN 版本
export AFL_USE_UBSAN=1
afl-clang-lto target.c -o target_ubsan
unset AFL_USE_UBSAN
