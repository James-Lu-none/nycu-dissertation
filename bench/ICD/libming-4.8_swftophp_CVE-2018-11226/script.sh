#!/bin/bash
FUZZER=${FUZZER_BIN:-afl-fuzz}
TARGET=${TARGET_BIN:-./swftophp}
tmux new-session -d -s swftophp -n "main" "$FUZZER -i in -o out -M main -- $TARGET @@"
