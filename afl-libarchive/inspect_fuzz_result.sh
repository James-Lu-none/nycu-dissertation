#!/bin/bash

mkdir -p profraws
# export LLVM_PROFILE_FILE="profraws/code-%p.profraw" # 這個指令會讓每個執行的實例產生一個獨立的 profraw 檔案，結果塞爆了硬碟

for file in /workspace/out/*/queue/id*; do
    LLVM_PROFILE_FILE="profraws/merged-%m.profraw" /workspace/target_cov "$file"
done

# 3. 合併數據
echo "正在合併數據..."
llvm-profdata-19 merge -sparse profraws/*.profraw -o merged.profdata

# 4. 生成 HTML 報表
echo "正在產出報表..."
llvm-cov-19 show ./target_cov -instr-profile=merged.profdata -format=html -output-dir=cov_report

echo "完成！請在瀏覽器打開 ./cov_report/index.html"