#!/bin/bash
#SBATCH --job-name=afl_bench
#SBATCH --partition=defq
#SBATCH --nodes=1
#SBATCH --cpus-per-task=1
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
  ACTIVE_METHODS=("base" "cd" "dd" "muoafl")
  MOD=4
else
  ACTIVE_METHODS=("dd" "muoafl")
  MOD=2
fi

IDX=$((SLURM_ARRAY_TASK_ID - 1))
TRIAL_NUM=$(( (IDX / MOD) + 1 ))
METHOD_IDX=$(( IDX % MOD ))
METHOD_NAME=${ACTIVE_METHODS[$METHOD_IDX]}

case $METHOD_NAME in
  "base")
    TARGET=$TARGET_BIN_BASE;     FUZZER="afl-fuzz";           NAME="base"
    ;;
  "cd")
    TARGET=$TARGET_BIN_CD;       FUZZER="afl-fuzz-cd";        NAME="cd"
    ;;
  "dd")
    TARGET=$TARGET_BIN_SOLO_DD;  FUZZER="afl-fuzz-solo-dd";   NAME="dd"
    ;;
  "muoafl")
    TARGET=$TARGET_BIN_MUOAFL; FUZZER="afl-fuzz-dd-muoafl"; NAME="muoafl"
    ;;
esac

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
  rm -rf "$LOCAL_OUT/${NAME}/queue" "$LOCAL_OUT/${NAME}/hangs" 2>/dev/null
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
mkdir -p out/.txt_sync
while true; do
  find . -maxdepth 1 -name '*.txt' -exec cp {} out/.txt_sync/ \; 2>/dev/null
  sleep 60
done
EOF
chmod +x "$LOCAL_OUT/sync_txt.sh"

echo "[*] Starting Fuzzer ($NAME)..."
apptainer exec \
  --cleanenv \
  --containall \
  --pid \
  --ipc \
  --no-home \
  --bind ${LOCAL_OUT}:/workspace/out \
  "$SANDBOX_DIR" \
  bash -c "cd /workspace || exit 1; /workspace/out/sync_txt.sh & exec ${FUZZER} -i /workspace/in -o /workspace/out -M ${NAME} -- ${TARGET} ${TARGET_ARGS}" &
FUZZER_PID=$!

# Background polling for live triage
(
  while true; do
    sleep 300
    echo "[*] [$(date)] Running live triage..." >> "$DEST_DIR/triage.log"
    python3 -u "${ROOT_DIR}/scripts/live_triage.py" --cve "$CVE" --image "$SANDBOX_DIR" --local-out "$LOCAL_OUT" $TARGET $TARGET_ARGS >> "$DEST_DIR/triage.log" 2>&1
    
    # Sync triage stats back to NFS
    mkdir -p "$DEST_DIR/out/${NAME}/crashes"
    cp "$LOCAL_OUT/${NAME}/crashes/.triage_stats" "$DEST_DIR/out/${NAME}/crashes/" 2>/dev/null || true
    cp "$LOCAL_OUT/${NAME}/crashes/.triaged_crashes" "$DEST_DIR/out/${NAME}/crashes/" 2>/dev/null || true
    
    if [ -f "$LOCAL_OUT/dgf_target_exposure.txt" ]; then
      echo "[+] TTE Found! Terminating fuzzer early..." >> "$DEST_DIR/triage.log"
      kill $FUZZER_PID 2>/dev/null
      break
    fi
  done
) &
TRIAGE_PID=$!

wait $FUZZER_PID
FUZZER_EXIT=$?

kill $TRIAGE_PID 2>/dev/null

if [ $FUZZER_EXIT -ne 0 ]; then
    echo "[-] Error: The fuzzer crashed! Exit code: $FUZZER_EXIT"
fi

exit 0