# llvm pass note

## some llvm basic concepts

1. in llvm code, functions are made of basic blocks, and basic blocks are made of instructions. so &F.front() gets the first basic block of function F, and &F.front().front() or &BB.front() gets the first instruction of that basic block.
2. Each instruction represents a low-level operation, such as arithmetic operations, memory access, control flow, etc.
3. LLVM ir is in static single assignment (SSA) form, meaning each variable is assigned exactly once and defined before use, so we can't set the previous register to itself plus one directly. instead, we need to load the value from memory, add one to it, and store it back to memory.

## compile and use llvm pass

```bash
clang++ -fPIC -shared rpfcc.cpp -o rpfcc.so \
  `llvm-config --cxxflags --ldflags --system-libs --libs core passes`

clang++ -O0 -fno-inline -S -emit-llvm main.cpp -o input.ll
opt -load-pass-plugin=./rpfcc.so -passes="rpfcc" input.ll -S -o output.ll
clang++ -O0 -fno-inline output.ll -o output
./output
```