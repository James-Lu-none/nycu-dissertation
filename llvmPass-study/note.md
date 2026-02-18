# llvm pass note

## some llvm basic concepts

1. in llvm code, functions are made of basic blocks, and basic blocks are made of instructions. so &F.front() gets the first basic block of function F, and &F.front().front() or &BB.front() gets the first instruction of that basic block.
2. Each instruction represents a low-level operation, such as arithmetic operations, memory access, control flow, etc.
3. LLVM ir is in static single assignment (SSA) form, meaning each variable is assigned exactly once and defined before use, so we can't set the previous register to itself plus one directly. instead, we need to load the value from memory, add one to it, and store it back to memory.

## AFL++執行前置作業

1. 讓程式崩潰時直接在當前目錄產生一個名為 core 的檔案，而不是啟動 Ubuntu 的錯誤報告產生器(Apport)，以此可以提升效能並確保 AFL++ 能夠正確偵測到程式崩潰的訊號。

    原本的設定:

    ```bash
    (.venv) user@super:~/workspace$ cat /proc/sys/kernel/core_pattern
    |/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E
    ```

    ```bash
    echo core | sudo tee /proc/sys/kernel/core_pattern
    ```

2. 確保核心轉儲（Core Dump）功能關閉，這樣當程式崩潰時不會產生數MB的 core 檔案。AFL++ 也不會去分析core檔案，而是直接監控程式的訊號（Signal）。

    ```bash
    ulimit -c 0
    ```

3. 切換 CPU 效能模式 (AFL++ 非常強烈建議，否則速度會很慢)

    ```bash
    sudo cpupower frequency-set -g performance
    ```

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

## 單純使用 dfsan 而不使用我自己寫的 pass plugin

```bash
# 比較用
clang++-18 -O0 -fno-inline -S -emit-llvm main.cpp -o output.ll

# 直接編譯成可執行檔，讓 Clang 處理 DFSAN 的 Runtime
clang++-18 -O0 -fno-inline -fsanitize=dataflow -no-pie main.cpp -o output.df
# 輸出llvm ir
clang++-18 -O0 -fno-inline -fsanitize=dataflow -S -emit-llvm main.cpp -o output.df.ll

# exclude printf function
clang++-18 -O0 -fno-inline -fsanitize=dataflow -no-pie -fsanitize-ignorelist=my_abi.txt main.cpp -o output.df.no_printf
# 輸出llvm ir
clang++-18 -O0 -fno-inline -fsanitize=dataflow -fsanitize-ignorelist=my_abi.txt -S -emit-llvm main.cpp -o output.df.no_printf.ll
```

### 問題與發現

1. 當執行 output 時，會出現錯誤訊息 FATAL: Code 0x628f21d85630 is out of application range. Non-PIE build? Segmentation fault (core dumped)

原因是 Linux 的 ASLR（位址空間隨機化）機制與 DFSan 的 Shadow Memory 佈局在「搶地盤」，需要透過 setarch -R 來關閉 ASLR，讓 DFSan 的 Shadow Memory 能夠成功劃分出它需要的標籤空間。
```bash
setarch `uname -m` -R ./output
```

官方文件的「間接說明」
在 LLVM DFSan 官方文件 中，雖然沒有直接寫「請執行 setarch -R」，但它提到了：

"DataFlowSanitizer uses a fixed memory mapping... The shadow memory is located at a fixed offset from the application memory."

這句話背後的含意是：DFSan 的運作依賴於硬編碼（Hard-coded）的虛擬位址區間。 * 衝突點： 如果系統開啟了 ASLR，Linux 核心可能會隨機地把堆疊（Stack）或共享函式庫（vDSO）放在 DFSan 預先定義好的「標籤區（Shadow Memory）」或「保留區（Reserved Space）」裡。

後果： 當 DFSan Runtime 啟動並檢查發現「這塊地已經被佔用了」，它就會報錯並結束.

2. 不論有沒有透過 -fsanitize-ignorelist=my_abi.txt 來排除 printf 函式，編譯出來的 output.ll 中， printf 函式都會被轉換成 printf.dfsan

當編譯器看到 printf 時，它會強制將其改名為 printf.dfsan。這個 printf.dfsan 其實是一個由 DFSan Runtime 提供的 Wrapper。

如果它是 uninstrumented： 這個 Wrapper 會負責把 DFSan 特有的標籤參數「剝離」，然後呼叫原始的、標準的 printf。
如果它是 custom： 這個 Wrapper 不僅會呼叫原始函式，還會根據預設規則（或你寫的規則）來計算並傳遞標籤（例如：讓輸出的回傳值也帶有汙點）。
之所以一定要更名，是因為 DFSan 必須確保所有的呼叫點（Call sites）在二進位層級上是統一的，避免直接撞上簽名不符的原始函式。