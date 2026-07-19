#!/bin/bash
FUZZER=${FUZZER_BIN:-afl-fuzz}
TARGET=${TARGET_BIN:-./target}
ROLE=${FUZZER_ROLE:-M}
NAME=${FUZZER_NAME:-main}
TARGET_ARGS=${TARGET_ARGS:-}

# Use the target binary's base name as the tmux session name
SESSION_NAME=$(basename "$TARGET")

LOG_FILE="/workspace/cpu_binding.log"

log_msg() {
  local msg="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [$NAME] $msg" | tee -a "$LOG_FILE"
}

if [ -z "$TARGET_BIN_ASAN" ]; then
  log_msg "[-] Error: TARGET_BIN_ASAN is not set!"
  exit 1
fi

if [ ! -f "$TARGET_BIN_ASAN" ]; then
  log_msg "[-] Error: SAND ASAN binary ($TARGET_BIN_ASAN) not found!"
  exit 1
fi
SAND_ARGS="-w $TARGET_BIN_ASAN"

while true; do
  log_msg "[*] Starting fuzzer inside tmux..."
  tmux kill-session -t "$SESSION_NAME" 2>/dev/null
  rm -rf out/$NAME
  
  # Copy compile-time metadata to the out/ directory so it gets synced to the host automatically
  cp /workspace/*.txt /workspace/*.csv out/ 2>/dev/null || true
  
  # Use exec to replace tmux shell process with fuzzer process.
  # TARGET_ARGS is unquoted to allow multiple arguments expansion or empty value.
  tmux new-session -d -s "$SESSION_NAME" -n "main" "exec $FUZZER -i in -o out -$ROLE $NAME $SAND_ARGS -- $TARGET $TARGET_ARGS"
  sleep 2.5
  
  MY_PID=$(tmux list-panes -t "$SESSION_NAME" -F "#{pane_pid}" 2>/dev/null)
  
  if [ -z "$MY_PID" ]; then
    log_msg "[!] Failed to get fuzzer PID. Retrying..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null
    sleep 1
    continue
  fi
  
  if [ -f "/proc/$MY_PID/status" ]; then
    MY_CORE=$(grep "Cpus_allowed_list:" /proc/$MY_PID/status | awk '{print $2}')
  else
    log_msg "[!] Fuzzer process died early. Retrying..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null
    sleep 1
    continue
  fi
  
  if [[ "$MY_CORE" == *"-"* ]] || [[ "$MY_CORE" == *","* ]] || [ -z "$MY_CORE" ]; then
    log_msg "[*] Fuzzer is not bound to a single core (core: $MY_CORE). Running without conflict checks."
    break
  fi
  
  log_msg "[*] My fuzzer (PID: $MY_PID) is bound to core: $MY_CORE"
  
  # Scan all the fuzzer processes in the system
  CONFLICT=false
  ALL_FUZZER_PIDS=$(pgrep -f "afl-fuzz")
  
  for OTHER_PID in $ALL_FUZZER_PIDS; do
    if [ "$OTHER_PID" -eq "$MY_PID" ]; then
      continue
    fi
    
    if [ -f "/proc/$OTHER_PID/status" ]; then
      OTHER_CORE=$(grep "Cpus_allowed_list:" /proc/$OTHER_PID/status | awk '{print $2}')
      if [ "$OTHER_CORE" = "$MY_CORE" ]; then
        log_msg "[!] Collision detected! PID $OTHER_PID is also on core $MY_CORE"
        if [ "$MY_PID" -gt "$OTHER_PID" ]; then
          log_msg "[!] My PID ($MY_PID) > Other PID ($OTHER_PID). I will yield and restart."
          CONFLICT=true
          break
        fi
      fi
    fi
  done
  
  if [ "$CONFLICT" = true ]; then
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null
    sleep 0.$((RANDOM % 9 + 1))
    continue
  else
    log_msg "[+] No conflicts detected. Fuzzer running smoothly on core $MY_CORE."
    break
  fi
done
