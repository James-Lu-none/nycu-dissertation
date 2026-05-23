export AFL_DGF_FILE=motivating_example.c
export AFL_DGF_LINE=26
# export AFL_DGF_FUNC=target/dgf.func.json
export AFL_DGF_MAX_DEPTH=100
afl-clang-lto -g -O0 motivating_example.c -o motivating_example
mkdir -p in
mkdir -p out
echo -n "AAAA" > in/seed

tmux new-session -d -s motivating-example -n "main" "afl-fuzz -i in -o out -M main -- ./motivating_example @@"

echo "Fuzzing session 'motivating-example' started!"
echo "Use 'tmux attach -t motivating-example' to see progress."
