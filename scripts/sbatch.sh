#!/bin/bash
#SBATCH --job-name=afl_bench
#SBATCH --partition=iais_cge_teacher
#SBATCH --nodes=1
#SBATCH --cpus-per-task=1
#SBATCH --output=logs/slurm-%A_%a.out

export APPTAINERENV_AFL_NO_AFFINITY=1

# Environment variables expected from manage_slurm.py:
# CVE, IMAGE_NAME, SESSION_ID, TRIAL_NAME, TARGET_BIN_BASE, TARGET_BIN_CD, TARGET_BIN_SOLO_DD, TARGET_BIN_DUAL_DD, TARGET_BIN_DUAL_CD, TARGET_ARGS

SESSION_ID=${SESSION_ID:-"exp_01"}
TRIAL_NAME=${TRIAL_NAME:-"bench"}
ROOT_DIR="/home/user/workspace/nycu-dissertation"

RUN_ALL=${RUN_ALL:-0}

if [ "$RUN_ALL" = "1" ]; then
  ACTIVE_ROLES=(0 1 2 3 4 5 6 7)
  MOD=8
else
  ACTIVE_ROLES=(4 5 6 7)
  MOD=4
fi

IDX=$((SLURM_ARRAY_TASK_ID - 1))
TRIAL_NUM=$(( (IDX / MOD) + 1 ))
ROLE_IDX=$(( IDX % MOD ))
ROLE_ID=${ACTIVE_ROLES[$ROLE_IDX]}

case $ROLE_ID in
  0) TARGET=$TARGET_BIN_BASE;    FUZZER="afl-fuzz";         ROLE="-M"; NAME="main";  METHOD="base" ;;
  1) TARGET=$TARGET_BIN_BASE;    FUZZER="afl-fuzz";         ROLE="-S"; NAME="slave"; METHOD="base" ;;
  2) TARGET=$TARGET_BIN_CD;      FUZZER="afl-fuzz-cd";      ROLE="-M"; NAME="main";  METHOD="cd"   ;;
  3) TARGET=$TARGET_BIN_CD;      FUZZER="afl-fuzz-cd";      ROLE="-S"; NAME="slave"; METHOD="cd"   ;;
  4) TARGET=$TARGET_BIN_SOLO_DD; FUZZER="afl-fuzz-solo-dd"; ROLE="-M"; NAME="main";  METHOD="dd"   ;;
  5) TARGET=$TARGET_BIN_SOLO_DD; FUZZER="afl-fuzz-solo-dd"; ROLE="-S"; NAME="slave"; METHOD="dd"   ;;
  6) TARGET=$TARGET_BIN_DUAL_DD; FUZZER="afl-fuzz-dual-dd"; ROLE="-M"; NAME="dd";    METHOD="dual-dd" ;;
  7) TARGET=$TARGET_BIN_DUAL_CD; FUZZER="afl-fuzz-dual-cd"; ROLE="-S"; NAME="cd";    METHOD="dual-cd" ;; 
esac

DEST_DIR="${ROOT_DIR}/artifact/${CVE}/${TRIAL_NAME}/${METHOD}/trial${TRIAL_NUM}"
LOCAL_OUT="/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}/out"

mkdir -p "$DEST_DIR"
mkdir -p "$LOCAL_OUT"

echo "[*] Starting Trial: $TRIAL_NUM, Role: $NAME, Target: $TARGET, Fuzzer: $FUZZER"
echo "[*] Dest dir: $DEST_DIR"
echo "[*] Local out: $LOCAL_OUT"

sync_data() {
  echo "[*] Syncing data to $DEST_DIR..."
  cp -a "$LOCAL_OUT/." "$DEST_DIR/"
}

cleanup() {
  echo "[*] Job ending. Performing final sync..."
  sync_data
  echo "[*] Cleaning up local RAM disk storage..."
  rm -rf "/dev/shm/fuzz_${SLURM_JOB_ID}_${SLURM_ARRAY_TASK_ID}"
}

# Trap to sync data when job ends or is cancelled
trap cleanup EXIT SIGINT SIGTERM

# Background periodic sync every 5 minutes
(
  while true; do
    sleep 300
    sync_data
  done
) &
SYNC_PID=$!

# Run fuzzer natively with Apptainer
apptainer exec \
  --bind ${LOCAL_OUT}:/workspace/out \
  ${ROOT_DIR}/bench/${CVE}/${IMAGE_NAME}.sif \
  bash -c "cd /workspace && ${FUZZER} -i in -o out ${ROLE} ${NAME} -- ${TARGET} ${TARGET_ARGS}"

kill $SYNC_PID 2>/dev/null