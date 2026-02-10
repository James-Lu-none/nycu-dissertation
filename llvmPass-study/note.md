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

## error when not excluding main function

When we don't exclude the main function in our pass, we will get an error like this:

```
(.venv) user@super:~/workspace/nycu-dissertation/llvmPass-study$ make
clang++-18 -fPIC -shared rpfcc.cpp -o rpfcc.so `llvm-config --cxxflags --ldflags --system-libs --libs core passes`
clang++-18 -O0 -fno-inline -S -emit-llvm main.cpp -o input.ll
opt -load-pass-plugin=./rpfcc.so -passes="rpfcc" input.ll -S -o output.ll
clang++ -O0 -fsanitize=dataflow -fno-inline output.ll -o output
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: /tmp/output-266a39.o: in function `factorial(int) [clone .dfsan]':
main.cpp:(.text+0x65): undefined reference to `printf.dfsan'
/usr/bin/ld: /tmp/output-266a39.o: in function `main.dfsan':
main.cpp:(.text+0x14c): undefined reference to `printf.dfsan'
/usr/bin/ld: main.cpp:(.text+0x1ad): undefined reference to `printf.dfsan'
clang++: error: linker command failed with exit code 1 (use -v to see invocation)
make: *** [makefile:17: output] Error 1
```

when we exclude the main function:

```
(.venv) user@super:~/workspace/nycu-dissertation/llvmPass-study$ make
clang++-18 -fPIC -shared rpfcc.cpp -o rpfcc.so `llvm-config --cxxflags --ldflags --system-libs --libs core passes`
clang++-18 -O0 -fno-inline -S -emit-llvm main.cpp -o input.ll
opt -load-pass-plugin=./rpfcc.so -passes="rpfcc" input.ll -S -o output.ll
clang++ -O0 -fsanitize=dataflow -fno-inline output.ll -o output
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: /tmp/output-4d84b6.o: in function `factorial(int) [clone .dfsan]':
main.cpp:(.text+0x65): undefined reference to `printf.dfsan'
/usr/bin/ld: /tmp/output-4d84b6.o: in function `main.dfsan':
main.cpp:(.text+0x155): undefined reference to `printf.dfsan'
clang++: error: linker command failed with exit code 1 (use -v to see invocation)
make: *** [makefile:17: output] Error 1
```


## 以下的makefile可以完成編譯，但會有機率segment fault???，而且不會產生rpfcc的自定義的行為(輸出 functionName + count)

```makefile
CXX = clang++-18
# 這裡需要確保編譯 Pass 本身時包含 LLVM 的 Headers
CXXFLAGS_PASS = -fPIC -shared `llvm-config --cxxflags`
LDFLAGS_PASS = `llvm-config --ldflags --system-libs --libs core passes`

# 目標程式的 Flag
# 注意：要把 -fpass-plugin 掛在編譯命令中

all: rpfcc.so output

# 編譯你的 LLVM Pass
rpfcc.so: rpfcc.cpp
	$(CXX) $(CXXFLAGS_PASS) rpfcc.cpp -o rpfcc.so $(LDFLAGS_PASS)

# 直接使用 clang++ 一次完成編譯與連結，讓 Clang 處理 DFSAN 的 Runtime
output: rpfcc.so main.cpp
	$(CXX) -O0 -fno-inline -fsanitize=dataflow -fpass-plugin=./rpfcc.so main.cpp -o output

clean:
	rm -f rpfcc.so output
```