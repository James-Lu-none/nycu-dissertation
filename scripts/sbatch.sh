#!/bin/bash
#SBATCH --job-name=afl_bench
#SBATCH --partition=defq
#SBATCH --nodes=1
#SBATCH --cpus-per-task=1
#SBATCH --time=25:00:00
#SBATCH --output=logs/slurm-%A_%a.out
#SBATCH --mem-per-cpu=8G
#SBATCH --nodelist=dgx-cn01

export APPTAINERENV_AFL_NO_UI=1
export APPTAINERENV_AFL_NO_AFFINITY=1
export APPTAINERENV_AFL_SEMANTIC_MAP="/workspace/semantic_map.csv"

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

if [ -n "$ACTIVE_METHODS" ]; then
  IFS=':' read -r -a ACTIVE_METHODS_ARRAY <<< "$ACTIVE_METHODS"
else
  if [ "$RUN_ALL" = "1" ]; then
    ACTIVE_METHODS_ARRAY=("base" "cd" "dd" "muoafl-v1")
  else
    ACTIVE_METHODS_ARRAY=("dd" "muoafl-v1")
  fi
fi

MOD=${#ACTIVE_METHODS_ARRAY[@]}
IDX=$((SLURM_ARRAY_TASK_ID - 1))
TRIAL_NUM=$(( (IDX / MOD) + 1 ))
METHOD_IDX=$(( IDX % MOD ))
METHOD_NAME=${ACTIVE_METHODS_ARRAY[$METHOD_IDX]}

case $METHOD_NAME in
  "base")
    TARGET=$TARGET_BIN_BASE;     FUZZER="afl-fuzz"
    ;;
  "cd")
    TARGET=$TARGET_BIN_CD;       FUZZER="afl-fuzz-cd"
    ;;
  "dd")
    TARGET=$TARGET_BIN_SOLO_DD;  FUZZER="afl-fuzz-solo-dd"
    ;;
  muoafl-*)
    TAG=${METHOD_NAME#muoafl-}
    TARGET="${TARGET_BIN_BASE%-base}-dd-muoafl-${TAG}"
    FUZZER="afl-fuzz-dd-muoafl-${TAG}"
    ;;
esac

NAME="main"

SAFE_IMAGE_NAME=$(echo "$IMAGE_NAME" | tr ':' '_')
SHARED_SANDBOX="/dev/shm/apptainer_sandbox_${CVE}_${SAFE_IMAGE_NAME}"
LOCKFILE="${SHARED_SANDBOX}.lock"

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

cleanup_sandbox() {
  if [ -n "$SHARED_SANDBOX" ] && [ -n "$LOCKFILE" ]; then
    (
      flock 8
      if [ -f "${SHARED_SANDBOX}.refs" ]; then
        sed -i "/^${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}$/d" "${SHARED_SANDBOX}.refs"
        if [ ! -s "${SHARED_SANDBOX}.refs" ]; then
          echo "[*] Last task for this sandbox on this node. Cleaning up sandbox ($SHARED_SANDBOX)..."
          rm -rf "$SHARED_SANDBOX" "${SHARED_SANDBOX}.refs" "${SHARED_SANDBOX}.tmp" 2>/dev/null
          rm -f "$LOCKFILE" 2>/dev/null
        fi
      fi
    ) 8>> "$LOCKFILE"
  fi
}

cleanup_fast() {
  echo "[*] Abort signal received (scancel/timeout). Performing fast sync..."
  rm -rf "$LOCAL_OUT/${NAME}/queue" "$LOCAL_OUT/${NAME}/hangs" 2>/dev/null
  sync_data
  echo "[*] Cleaning up local RAM disk storage..."
  rm -rf "/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}"
  cleanup_sandbox
  exit 0
}

cleanup_normal() {
  echo "[*] Job completed naturally. Performing final sync..."
  sync_data
  echo "[*] Cleaning up local RAM disk storage..."
  rm -rf "/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}"
  cleanup_sandbox
}

trap cleanup_fast SIGINT SIGTERM
trap cleanup_normal EXIT

# use a shared sandbox per compute node for the same CVE and IMAGE to drastically save RAM,
# prevent "Too many open files in system", and avoid extracting hundreds of thousands of files multiple times.

# Use flock to ensure only the first job on the node builds the sandbox
exec 9> "$LOCKFILE"
flock 9
SIF_PATH="${ROOT_DIR}/bench/${CVE}/${IMAGE_NAME}.sif"
if [ ! -d "$SHARED_SANDBOX" ] || [ "$SIF_PATH" -nt "$SHARED_SANDBOX" ]; then
    echo "[*] Building (or Rebuilding) Shared Apptainer Sandbox in RAM ($SHARED_SANDBOX)..."
    rm -rf "$SHARED_SANDBOX" "${SHARED_SANDBOX}.tmp" "${SHARED_SANDBOX}.refs" 2>/dev/null
    ulimit -n 1048576 2>/dev/null || ulimit -n 65536 2>/dev/null || true
    apptainer build --sandbox "${SHARED_SANDBOX}.tmp" "$SIF_PATH"
    mv "${SHARED_SANDBOX}.tmp" "$SHARED_SANDBOX"
    touch "$SHARED_SANDBOX"
else
    echo "[*] Shared Sandbox already exists and is up to date. Reusing it to save time and RAM!"
fi
echo "${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}" >> "${SHARED_SANDBOX}.refs"
flock -u 9

SANDBOX_DIR="$SHARED_SANDBOX"


echo "[*] Starting Fuzzer ($NAME)..."
apptainer exec \
  --cleanenv \
  --containall \
  --pid \
  --ipc \
  --no-home \
  --bind ${LOCAL_OUT}:/workspace/out \
  "$SANDBOX_DIR" \
  bash -c "cd /workspace || exit 1; if [ -z \"${TARGET_BIN_ASAN}\" ] || [ ! -f \"${TARGET_BIN_ASAN}\" ]; then echo \"[-] Error: SAND ASAN binary (${TARGET_BIN_ASAN}) not found or unset!\" >&2; exit 1; fi; cp *.txt *.csv out/ 2>/dev/null || true; exec ${FUZZER} -i /workspace/in -o /workspace/out -M ${NAME} -w ${TARGET_BIN_ASAN} -- ${TARGET} ${TARGET_ARGS}" &
FUZZER_PID=$!

# Background polling for live triage
(
  while true; do
    sleep 150
    echo "[*] [$(date)] Running live triage..." >> "$DEST_DIR/triage.log"
    python3 -u "${ROOT_DIR}/scripts/live_triage.py" --cve "$CVE" --image "$SANDBOX_DIR" --local-out "$LOCAL_OUT" $TARGET $TARGET_ARGS >> "$DEST_DIR/triage.log" 2>&1
    
    # Sync triage stats back to NFS
    mkdir -p "$DEST_DIR/out/${NAME}/crashes"
    cp "$LOCAL_OUT/${NAME}/crashes/.triage_stats" "$DEST_DIR/out/${NAME}/crashes/" 2>/dev/null || true
    cp "$LOCAL_OUT/${NAME}/crashes/.triaged_crashes" "$DEST_DIR/out/${NAME}/crashes/" 2>/dev/null || true
    
    if [ -s "$LOCAL_OUT/tte.txt" ]; then
      echo "[+] TTE Found! Terminating fuzzer early..." >> "$DEST_DIR/triage.log"
      kill $FUZZER_PID 2>/dev/null
      break
    fi
  done
) &
TRIAGE_PID=$!

# Background polling for hourly full sync
(
  while true; do
    sleep 3600
    echo "[*] [$(date)] Performing hourly full sync..." >> "$DEST_DIR/triage.log"
    sync_data
  done
) &
SYNC_PID=$!

wait $FUZZER_PID
FUZZER_EXIT=$?

kill $TRIAGE_PID 2>/dev/null
kill $SYNC_PID 2>/dev/null

if [ $FUZZER_EXIT -ne 0 ]; then
    echo "[-] Error: The fuzzer crashed! Exit code: $FUZZER_EXIT"
fi

exit 0