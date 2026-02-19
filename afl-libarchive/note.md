# libarchive 編譯/fuzzing 記錄

## target_cov 編譯 debug 紀錄

```Dockerfile
WORKDIR /workspace
RUN afl-clang-lto++ \
    -I/src/libarchive/libarchive -I/src/libarchive/build_cov/libarchive \
    /src/libarchive_fuzzer.cc -o /workspace/target_cov \
    /deps/libarchive_cov.a \
    /deps/libxml2_cov.a \
    -Wl,-Bstatic -llzo2 -llzma -llz4 -lbz2 -lz -lzstd \
    -Wl,-Bdynamic -lcrypto -lacl -lm -ldl -lpthread \
    /usr/local/lib/afl/libAFLDriver.a
```
以上指令編譯後的 ./target_cov 雖然能成功執行，但不會產出任何 profraw 檔案，因為沒有包含 -fprofile-instr-generate，所以沒有在結階段自動拉入包含 __llvm_profile_write_file 實作的庫。

```bash
LLVM_PROFILE_FILE="test.profraw" ./target_cov out/main/queue/id:000000*
Reading 10 bytes from out/main/queue/id:000000,time:0,execs:0,orig:seed
Execution successful.
```

以下是 `target_cov` 的編譯指令，包含了 AFL++ 的覆蓋率相關選項：
```Dockerfile
WORKDIR /workspace
RUN afl-clang-lto++ -fprofile-instr-generate -fcoverage-mapping \
    -I/src/libarchive/libarchive -I/src/libarchive/build_cov/libarchive \
    /src/libarchive_fuzzer.cc -o /workspace/target_cov \
    /deps/libarchive_cov.a \
    /deps/libxml2_cov.a \
    -Wl,-Bstatic -llzo2 -llzma -llz4 -lbz2 -lz -lzstd \
    -Wl,-Bdynamic -lcrypto -lacl -lm -ldl -lpthread \
    /usr/local/lib/afl/libAFLDriver.a
```

雖然AI建議在harness程式碼中加入 `__llvm_profile_write_file()` 以確保覆蓋率資料被寫入，但實際上在使用 AFL++ 的覆蓋率模式時，這個函式會在程式結束時自動被呼叫，因此不需要手動加入。

libarchive_fuzzer_cov.cc 
```cpp
// 宣告 LLVM 覆蓋率手動寫入函式
extern "C" int __llvm_profile_write_file(void);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  ...
  // --- 關鍵步驟：強迫 LLVM 寫入覆蓋率數據 ---
  __llvm_profile_write_file();

  return 0;
}
```