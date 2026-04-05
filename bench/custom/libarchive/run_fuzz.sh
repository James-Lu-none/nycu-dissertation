#!/bin/bash

SESSION="fuzz_session"
INPUT_DIR="./in"
OUTPUT_DIR="./out"

mkdir -p $INPUT_DIR
mkdir -p $OUTPUT_DIR

# 1. 建立 Session 並啟動 Main 實例
tmux new-session -d -s $SESSION -n "main" "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -M main -- ./target_normal @@"

# 2. 建立 Sanitizer 視窗
tmux new-window -t $SESSION -n "asan" "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -S slave_asan -- ./target_asan @@"
# tmux new-window -t $SESSION -n "msan" "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -S slave_msan -- ./target_msan @@"
# tmux new-window -t $SESSION -n "ubsan" "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -S slave_ubsan -- ./target_ubsan @@"


# 3. 建立 CMPLOG 視窗
# https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.cmplog.md
tmux new-window -t $SESSION -n "cmplog" "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -S slave_cmplog -c ./target_cmplog -m none -- ./target_normal @@"

# 4. 建立其餘 5 個普通 Slaves 視窗
for i in {1..5}
do
    tmux new-window -t $SESSION -n "slave_$i" "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -S slave_normal_$i -- ./target_normal @@"
done

echo "Fuzzing session '$SESSION' started!"
echo "Use 'tmux attach -t $SESSION' to see progress."