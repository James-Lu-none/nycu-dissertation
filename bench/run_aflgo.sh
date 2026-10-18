#!/bin/bash
# AFLGo Runner script with dynamic annealing horizon and non-destructive output handling.
# Compatible with nycu-dissertation container orchestration and triage pipeline.

FUZZER=${FUZZER_BIN:-afl-fuzz}
TARGET=${TARGET_BIN:-./target}
ROLE=${FUZZER_ROLE:-M}
NAME=${FUZZER_NAME:-main}
TARGET_ARGS=${TARGET_ARGS:-}
CONTAINER_NAME=${CONTAINER_NAME:-$(hostname)}

SESSION_NAME=$(basename "$TARGET")
LOG_FILE="/workspace/cpu_binding.log"
mkdir -p /workspace/logs /workspace/out

log_msg() {
  local msg="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [$NAME] $msg" | tee -a "$LOG_FILE"
}

# Determine annealing horizon (-c): default to 80% of MAX_TIME or 240m
if [ -n "${MAX_TIME:-}" ] && [ "$MAX_TIME" -gt 0 ] 2>/dev/null; then
  CALC_MIN=$(( MAX_TIME * 8 / 10 / 60 ))
  if [ "$CALC_MIN" -lt 1 ]; then
    CALC_MIN=1
  fi
  ANNEALING_TIME="${CALC_MIN}m"
else
  ANNEALING_TIME="${ANNEALING_TIME:-240m}"
fi

log_msg "[*] AFLGo Target: $TARGET"
log_msg "[*] Annealing horizon (-c): $ANNEALING_TIME"

# Copy metadata to out/ for automatic syncing to host
cp /workspace/*.txt /workspace/*.json /workspace/*.jsonl out/ 2>/dev/null || true

# Write run manifest
cat << EOF > "/workspace/logs/run_manifest_${CONTAINER_NAME}.json"
{
  "container": "${CONTAINER_NAME}",
  "fuzzer": "${FUZZER}",
  "target": "${TARGET}",
  "target_args": "${TARGET_ARGS}",
  "role": "${ROLE}",
  "name": "${NAME}",
  "annealing_time": "${ANNEALING_TIME}",
  "start_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1

while true; do
  log_msg "[*] Starting AFLGo fuzzer inside tmux session: $SESSION_NAME..."
  tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true

  # Start AFLGo inside tmux. Note: Do NOT delete out/$NAME!
  tmux new-session -d -s "$SESSION_NAME" -n "main" \
    "AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 exec $FUZZER -m none -z exp -c $ANNEALING_TIME -i in -o out -$ROLE $NAME -- $TARGET $TARGET_ARGS > /workspace/logs/${CONTAINER_NAME}.log 2>&1"

  sleep 2.5

  MY_PID=$(tmux list-panes -t "$SESSION_NAME" -F "#{pane_pid}" 2>/dev/null)

  if [ -z "$MY_PID" ]; then
    log_msg "[!] Failed to get fuzzer PID. Retrying..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
    sleep 1
    continue
  fi

  if [ -f "/proc/$MY_PID/status" ]; then
    MY_CORE=$(grep "Cpus_allowed_list:" /proc/$MY_PID/status | awk '{print $2}')
  else
    log_msg "[!] Fuzzer process died early. Retrying..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
    sleep 1
    continue
  fi

  if [[ "$MY_CORE" == *"-"* ]] || [[ "$MY_CORE" == *","* ]] || [ -z "$MY_CORE" ]; then
    log_msg "[*] Fuzzer is not bound to a single core (core: $MY_CORE). Running without conflict checks."
    break
  fi

  log_msg "[*] My fuzzer (PID: $MY_PID) is bound to core: $MY_CORE"

  # Scan for core collisions across fuzzer processes
  CONFLICT=false
  ALL_FUZZER_PIDS=$(pgrep -f "afl-fuzz" || true)

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
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
    sleep 0.$((RANDOM % 9 + 1))
    continue
  else
    log_msg "[+] No conflicts detected. Fuzzer running smoothly on core $MY_CORE."
    break
  fi
done

# Keep script running while tmux session exists
while tmux has-session -t "$SESSION_NAME" 2>/dev/null; do
  sleep 5
done

log_msg "[*] Tmux session terminated. Preserving out/ directory."
