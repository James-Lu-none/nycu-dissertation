#!/bin/bash
FUZZER=${FUZZER_BIN:-afl-fuzz}
TARGET=${TARGET_BIN:-./swftophp}
ROLE=${FUZZER_ROLE:-M}
NAME=${FUZZER_NAME:-main}
tmux new-session -d -s swftophp -n "main" "$FUZZER -i in -o out -$ROLE $NAME -- $TARGET @@"
