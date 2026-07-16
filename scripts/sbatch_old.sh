#!/bin/bash
#SBATCH --job-name=afl_bench
#SBATCH --partition=iais_cge_teacher
#SBATCH --nodes=1
#SBATCH --cpus-per-task=2
#SBATCH --time=25:00:00
#SBATCH --output=logs/slurm-%A_%a.out
#SBATCH --mem-per-cpu=8G

export APPTAINERENV_AFL_NO_UI=1
export APPTAINERENV_AFL_NO_AFFINITY=1

# Use RAM disk for Apptainer cache to avoid hammering the NFS /home directory
export APPTAINER_CACHEDIR="/dev/shm/${USER}_apptainer_cache"
export APPTAINER_TMPDIR="/dev/shm/${USER}_apptainer_tmp"
mkdir -p "$APPTAINER_CACHEDIR" "$APPTAINER_TMPDIR"

# Environment variables expected from manage_slurm.py:
# CVE, IMAGE_NAME, SESSION_ID, TRIAL_NAME, TARGET_BIN_BASE, TARGET_BIN_CD, TARGET_BIN_SOLO_DD, TARGET_BIN_DUAL_DD, TARGET_BIN_DUAL_CD, TARGET_ARGS

SESSION_ID=${SESSION_ID:-"exp_01"}
TRIAL_NAME=${TRIAL_NAME:-"bench"}

ROOT_DIR="${HOME}/workspace/nycu-dissertation"
RUN_ALL=${RUN_ALL:-0}

if [ "$RUN_ALL" = "1" ]; then
  ACTIVE_METHODS=("base" "cd" "dd" "dual")
  MOD=4
else
  ACTIVE_METHODS=("dd" "dual")
  MOD=2
fi

IDX=$((SLURM_ARRAY_TASK_ID - 1))
TRIAL_NUM=$(( (IDX / MOD) + 1 ))
METHOD_IDX=$(( IDX % MOD ))
METHOD_NAME=${ACTIVE_METHODS[$METHOD_IDX]}

case $METHOD_NAME in
  "base")
    M_TARGET=$TARGET_BIN_BASE;     M_FUZZER="afl-fuzz"
    S_TARGET=$TARGET_BIN_BASE;     S_FUZZER="afl-fuzz"
    ;;
  "cd")
    M_TARGET=$TARGET_BIN_CD;       M_FUZZER="afl-fuzz-cd"
    S_TARGET=$TARGET_BIN_CD;       S_FUZZER="afl-fuzz-cd"
    ;;
  "dd")
    M_TARGET=$TARGET_BIN_SOLO_DD;  M_FUZZER="afl-fuzz-solo-dd"
    S_TARGET=$TARGET_BIN_SOLO_DD;  S_FUZZER="afl-fuzz-solo-dd"
    ;;
  "dual")
    M_TARGET=$TARGET_BIN_DUAL_DD;  M_FUZZER="afl-fuzz-dual-dd"
    S_TARGET=$TARGET_BIN_DUAL_CD;  S_FUZZER="afl-fuzz-dual-cd"
    ;;
esac

M_NAME="main"
S_NAME="slave"

DEST_DIR="${ROOT_DIR}/artifact/${CVE}/${TRIAL_NAME}/${METHOD_NAME}/trial${TRIAL_NUM}"
LOCAL_OUT="/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}/out"

mkdir -p "$DEST_DIR"
mkdir -p "$LOCAL_OUT"

echo "[*] Starting Trial: $TRIAL_NUM, Method: $METHOD_NAME"
echo "[*] Dest dir: $DEST_DIR"
echo "[*] Local out: $LOCAL_OUT"

sync_data() {
  echo "[*] Syncing data to $DEST_DIR..."
  mkdir -p "$DEST_DIR/out"
  cp -a "$LOCAL_OUT/"* "$DEST_DIR/out/" 2>/dev/null || true
  
  if [ -d "$DEST_DIR/out/.txt_sync" ]; then
    mv "$DEST_DIR/out/.txt_sync"/*.txt "$DEST_DIR/" 2>/dev/null || true
    rm -rf "$DEST_DIR/out/.txt_sync"
  fi
}

cleanup_fast() {
  echo "[*] Abort signal received (scancel/timeout). Performing fast sync..."
  # Discard massive queue/hangs directories to ensure sync completes before SIGKILL (30s)
  rm -rf "$LOCAL_OUT/${M_NAME}/queue" "$LOCAL_OUT/${S_NAME}/queue" "$LOCAL_OUT/${M_NAME}/hangs" "$LOCAL_OUT/${S_NAME}/hangs" 2>/dev/null
  sync_data
  echo "[*] Cleaning up local RAM disk storage..."
  rm -rf "/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}"
  exit 0
}

cleanup_normal() {
  echo "[*] Job completed naturally. Performing final sync..."
  sync_data
  echo "[*] Cleaning up local RAM disk storage..."
  rm -rf "/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}"
}

trap cleanup_fast SIGINT SIGTERM
trap cleanup_normal EXIT

SANDBOX_DIR="/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}/sandbox"
echo "[*] Building Apptainer Sandbox in RAM ($SANDBOX_DIR)..."
apptainer build --sandbox "$SANDBOX_DIR" "${ROOT_DIR}/bench/${CVE}/${IMAGE_NAME}.sif"

cat << 'EOF' > "$LOCAL_OUT/sync_txt.sh"
#!/bin/bash
MODE=$1
mkdir -p out/.txt_sync
while true; do
  if [ "$MODE" == "main" ] || [ "$MODE" == "dd" ]; then
    find . -maxdepth 1 -name '*.txt' -exec cp {} out/.txt_sync/ \; 2>/dev/null
  else
    for f in *.txt; do
      [ -f "$f" ] || continue
      if [[ "$f" == *_slave.txt ]] || [[ "$f" == *_cd.txt ]]; then
        cp "$f" "out/.txt_sync/$f" 2>/dev/null
      else
        cp "$f" "out/.txt_sync/${f%.txt}_${MODE}.txt" 2>/dev/null
      fi
    done
  fi
  sleep 60
done
EOF
chmod +x "$LOCAL_OUT/sync_txt.sh"

echo "[*] Starting Main Fuzzer ($M_NAME)..."
apptainer exec \
  --cleanenv \
  --containall \
  --pid \
  --ipc \
  --no-home \
  --bind ${LOCAL_OUT}:/workspace/out \
  "$SANDBOX_DIR" \
  bash -c "cd /workspace || exit 1; /workspace/out/sync_txt.sh main & exec ${M_FUZZER} -i /workspace/in -o /workspace/out -M ${M_NAME} -- ${M_TARGET} ${TARGET_ARGS}" &
MAIN_PID=$!

sleep 2

echo "[*] Starting Slave Fuzzer ($S_NAME)..."
apptainer exec \
  --cleanenv \
  --containall \
  --pid \
  --ipc \
  --no-home \
  --bind ${LOCAL_OUT}:/workspace/out \
  "$SANDBOX_DIR" \
  bash -c "cd /workspace || exit 1; /workspace/out/sync_txt.sh slave & exec ${S_FUZZER} -i /workspace/in -o /workspace/out -S ${S_NAME} -- ${S_TARGET} ${TARGET_ARGS}" &
SLAVE_PID=$!

# Background polling for live triage
(
  while true; do
    sleep 60
    echo "[*] [$(date)] Running live triage..." >> "$DEST_DIR/triage.log"
    python3 -u "${ROOT_DIR}/scripts/live_triage.py" --cve "$CVE" --image "$SANDBOX_DIR" --local-out "$LOCAL_OUT" $M_TARGET $TARGET_ARGS >> "$DEST_DIR/triage.log" 2>&1
    
    # Sync triage stats back to NFS
    mkdir -p "$DEST_DIR/out/${M_NAME}/crashes" "$DEST_DIR/out/${S_NAME}/crashes"
    cp "$LOCAL_OUT/${M_NAME}/crashes/.triage_stats" "$DEST_DIR/out/${M_NAME}/crashes/" 2>/dev/null || true
    cp "$LOCAL_OUT/${M_NAME}/crashes/.triaged_crashes" "$DEST_DIR/out/${M_NAME}/crashes/" 2>/dev/null || true
    cp "$LOCAL_OUT/${S_NAME}/crashes/.triage_stats" "$DEST_DIR/out/${S_NAME}/crashes/" 2>/dev/null || true
    cp "$LOCAL_OUT/${S_NAME}/crashes/.triaged_crashes" "$DEST_DIR/out/${S_NAME}/crashes/" 2>/dev/null || true
    
    if [ -s "$LOCAL_OUT/tte.txt" ]; then
      echo "[+] TTE Found! Terminating fuzzers early..." >> "$DEST_DIR/triage.log"
      kill $MAIN_PID $SLAVE_PID 2>/dev/null
      break
    fi
  done
) &
TRIAGE_PID=$!

wait $MAIN_PID
MAIN_EXIT=$?
wait $SLAVE_PID
SLAVE_EXIT=$?

kill $TRIAGE_PID 2>/dev/null

if [ $MAIN_EXIT -ne 0 ] || [ $SLAVE_EXIT -ne 0 ]; then
    echo "[-] Error: One of the fuzzers crashed! Main: $MAIN_EXIT, Slave: $SLAVE_EXIT"
fi

exit 0