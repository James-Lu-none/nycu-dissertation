#!/bin/bash

# clang++ --coverage -o target_gcov target.c

# afl-cov -d ./out --live --code-dir ./src_code/ -c "./target_gcov @@" --all-tests
clang -fprofile-instr-generate -fcoverage-mapping -O0 target.c -o target_cov

mkdir -p profraws
export LLVM_PROFILE_FILE="profraws/code-%p.profraw"

find ./out -type f -path "*/queue/id*" | while read -r testcase; do
    ./target_cov "$testcase" > /dev/null 2>&1
done

# 3. 合併數據
echo "正在合併數據..."
llvm-profdata-19 merge -sparse profraws/*.profraw -o merged.profdata

# 4. 生成 HTML 報表
echo "正在產出報表..."
llvm-cov-19 show ./target_cov -instr-profile=merged.profdata -format=html -output-dir=cov_report

echo "完成！請在瀏覽器打開 ./cov_report/index.html"