#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_usage() {
  echo "Usage: $0 <duration_in_seconds> <cve_name>"
  echo "Example: $0 3600 libming-4.7_swftophp_CVE-2017-9988"
  exit 1
}

# 1. Parse and validate arguments
if [ "$#" -lt 2 ]; then
  show_usage
fi

DURATION="$1"
CVE="$2"

if [[ ! "$DURATION" =~ ^[0-9]+$ ]]; then
  echo "Error: Duration must be a positive integer (seconds)."
  show_usage
fi

if [ ! -d "$ROOT_DIR/bench/$CVE" ]; then
  echo "Error: Benchmark directory '$ROOT_DIR/bench/$CVE' does not exist."
  exit 1
fi

echo -e "\033[1;32m[Loop Runner] Initialized for CVE: $CVE\033[0m"
echo -e "\033[1;32m[Loop Runner] Run duration per trial: $DURATION seconds\033[0m"

iteration=1
while true; do
  echo -e "\n\033[1;34m==================================================\033[0m"
  echo -e "\033[1;34m[Iteration $iteration] Start Time: $(date)\033[0m"
  echo -e "\033[1;34m==================================================\033[0m"

  # Step A: Start containers using up command non-interactively
  echo -e "\n\033[1;33m[Step 1/4] Starting containers...\033[0m"
  "$ROOT_DIR/manage.sh" up "$CVE" 12 -y

  # Step B: Wait for the duration
  echo -e "\n\033[1;33m[Step 2/4] Fuzzing for $DURATION seconds...\033[0m"
  
  # Determine sleep intervals for printing progress updates
  sleep_interval=60
  if [ "$DURATION" -lt 60 ]; then
    sleep_interval=10
  fi
  if [ "$DURATION" -lt 10 ]; then
    sleep_interval=1
  fi

  elapsed=0
  while [ $elapsed -lt "$DURATION" ]; do
    remaining=$((DURATION - elapsed))
    if [ $remaining -lt $sleep_interval ]; then
      sleep $remaining
      elapsed=$DURATION
    else
      sleep $sleep_interval
      elapsed=$((elapsed + sleep_interval))
      echo -e "  -> Elapsed: $elapsed/$DURATION seconds..."
    fi
  done

  # Step C: Copy results
  echo -e "\n\033[1;33m[Step 3/4] Copying trial results...\033[0m"
  "$ROOT_DIR/manage.sh" copy "$CVE"

  # Step D: Shut down containers
  echo -e "\n\033[1;33m[Step 4/4] Stopping containers and removing volumes...\033[0m"
  "$ROOT_DIR/manage.sh" down "$CVE" -y

  # Extra: Run TTE check on the latest trial directory
  echo -e "\n\033[1;35m[Post-processing] Running TTE check...\033[0m"
  "$ROOT_DIR/manage.sh" tte_check "$CVE" -y

  echo -e "\n\033[1;32m[Iteration $iteration] Completed. Resting 5 seconds before next iteration...\033[0m"
  sleep 5
  iteration=$((iteration + 1))
done
