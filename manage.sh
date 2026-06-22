#!/bin/bash

# Root directory helper
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to extract active CVEs from cves.env or cves.env.template
get_cves() {
  if [ -f "$ROOT_DIR/cves.env" ]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$line" ]] && continue
      echo "$line" | tr -d '"' | tr -d "'" | tr -d ' ' | tr -d '\r'
    done < "$ROOT_DIR/cves.env"
  elif [ -f "$ROOT_DIR/cves.env.template" ]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$line" ]] && continue
      echo "$line" | tr -d '"' | tr -d "'" | tr -d ' ' | tr -d '\r'
    done < "$ROOT_DIR/cves.env.template"
  else
    # Fallback to directories under bench/ containing .env
    find "$ROOT_DIR/bench" -maxdepth 2 -name ".env" | xargs -I {} dirname {} | xargs -I {} basename {}
  fi
}


show_usage() {
  echo "Usage: $0 {up|down|build|status|log|clean|copy|stat_plot|tte_check|tte_plot|ttr} [cve_name]"
  echo "Commands:"
  echo "  up        : Start docker containers for CVE trials"
  echo "  down      : Stop docker containers and remove named volumes (-v)"
  echo "  build     : Build docker images for CVE trials"
  echo "  status    : Check if fuzzer process is active inside containers"
  echo "  log       : Print /workspace/cpu_binding.log from inside containers"
  echo "  clean     : Force stop and remove containers, volumes, and images"
  echo "  copy      : Copy stats from docker containers (excluding .cur_input)"
  echo "  stat_plot : Run stat_plot.py on active CVEs (plots already copied stats)"
  echo "  tte_check : Run TTE_check.py on active CVEs"
  echo "  tte_plot  : Run TTE_plot.py on active CVEs"
  echo "  ttr       : Run TTR.py on active CVEs (copies TTR logs/stats and plots)"
  echo ""
  echo "If [cve_name] is omitted, the command runs on all active CVEs defined in cves.env."
  exit 1
}

COMMAND=""
TARGET_CVE=""
EXTRA_ARGS=()

for arg in "$@"; do
  # Convert arg to lowercase to accept case-insensitive commands
  arg_lower=$(echo "$arg" | tr '[:upper:]' '[:lower:]')
  if [ -z "$COMMAND" ] && [[ "$arg_lower" =~ ^(up|down|build|status|log|clean|copy|stat_plot|tte_check|tte_plot|ttr)$ ]]; then
    COMMAND="$arg_lower"
  elif [[ "$arg" == -* ]]; then
    EXTRA_ARGS+=("$arg")
  else
    if [ -z "$TARGET_CVE" ]; then
      TARGET_CVE="$arg"
    else
      EXTRA_ARGS+=("$arg")
    fi
  fi
done

if [ -z "$COMMAND" ]; then
  echo "Error: Command (up, down, build, status, log, clean, copy, stat_plot, tte_check, tte_plot, ttr) is required."
  show_usage
fi

# Determine target CVEs
if [ "$COMMAND" = "down" ]; then
  # For down command, always force interactive number selection and 2-step confirmation
  ALL_CVES=($(get_cves))
  if [ ${#ALL_CVES[@]} -eq 0 ]; then
    echo "No active CVEs found to down."
    exit 0
  fi
  echo "CVE list:"
  for i in "${!ALL_CVES[@]}"; do
    echo "$((i+1)). ${ALL_CVES[$i]}"
  done
  
  read -p "Select a CVE to down (1-${#ALL_CVES[@]}): " selection
  if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#ALL_CVES[@]}" ]; then
    echo "Error: Invalid selection."
    exit 1
  fi
  
  TARGET_CVE="${ALL_CVES[$((selection-1))]}"
  CVE_LIST=("$TARGET_CVE")
  
  echo -e "\nSelected CVE: \033[1;33m$TARGET_CVE\033[0m"
  read -p "Are you sure you want to stop and remove volumes for $TARGET_CVE? (y/N): " confirm1
  if [[ ! "$confirm1" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
elif [ "$COMMAND" = "up" ]; then
  # For up command, always force interactive number selection without confirmation
  ALL_CVES=($(get_cves))
  if [ ${#ALL_CVES[@]} -eq 0 ]; then
    echo "No active CVEs found to up."
    exit 0
  fi
  echo "CVE list:"
  for i in "${!ALL_CVES[@]}"; do
    echo "$((i+1)). ${ALL_CVES[$i]}"
  done
  
  read -p "Select a CVE to up (1-${#ALL_CVES[@]}): " selection
  if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#ALL_CVES[@]}" ]; then
    echo "Error: Invalid selection."
    exit 1
  fi
  
  TARGET_CVE="${ALL_CVES[$((selection-1))]}"
  CVE_LIST=("$TARGET_CVE")
  
  echo -e "\nSelected CVE: \033[1;33m$TARGET_CVE\033[0m"
elif [ -n "$TARGET_CVE" ]; then
  # Verify directory exists under bench/
  if [ ! -d "$ROOT_DIR/bench/$TARGET_CVE" ]; then
    echo "Error: Benchmark directory 'bench/$TARGET_CVE' not found."
    exit 1
  fi
  CVE_LIST=("$TARGET_CVE")
else
  # Read active list
  CVE_LIST=($(get_cves))
fi

if [ ${#CVE_LIST[@]} -eq 0 ] && [ "$COMMAND" != "clean" ]; then
  echo "No active CVEs found to manage."
  exit 0
fi

if [ "$COMMAND" = "clean" ]; then
  echo -e "\n\033[1;31m[Docker-Prune] Stopping and removing all containers & pruning volumes...\033[0m"
  CONTAINER_IDS=$(docker ps -aq)
  if [ -n "$CONTAINER_IDS" ]; then
    echo "Stopping all containers..."
    docker stop $CONTAINER_IDS || true
    echo "Removing all containers..."
    docker rm $CONTAINER_IDS || true
  else
    echo "No containers to stop/remove."
  fi
  echo "Pruning all unused volumes..."
  docker volume prune -a -f
  
  echo -e "\n\033[1;34m[Docker Volumes]\033[0m"
  docker volume ls
  
  echo -e "\n\033[1;34m[Docker Containers]\033[0m"
  docker ps -a
  
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

if [ "$COMMAND" = "copy" ]; then
  cd "$ROOT_DIR"
  trial=(1 2 3 4 5)
  methods=("base" "dd" "cd" "dual-dd" "dual-cd")
  suffixes=("afl-base" "afl-dd" "afl-cd" "afl-dual-dd" "afl-dual-cd")
  for CVE in "${CVE_LIST[@]}"; do
    root="./artifact/${CVE}"
    mkdir -p "${root}"
    for i in "${trial[@]}"; do
      for idx in "${!methods[@]}"; do
        method="${methods[$idx]}"
        suffix="${suffixes[$idx]}"
        mkdir -p "${root}/${method}/trial${i}"
        printf "Copying results from %-55s... " "${CVE}-${suffix}-${i}"
        if [ "$(docker inspect -f '{{.State.Running}}' "${CVE}-${suffix}-${i}" 2>/dev/null)" = "true" ]; then
          docker exec "${CVE}-${suffix}-${i}" tar -cf - -C /workspace out --exclude=".cur_input" --exclude="*.pyc" --exclude="__pycache__" 2>/dev/null | tar -xf - -C "${root}/${method}/trial${i}/" 2>/dev/null || true
        else
          docker cp "${CVE}-${suffix}-${i}:/workspace/out" "${root}/${method}/trial${i}/" 2>/dev/null || true
        fi
        sudo find "${root}/${method}/trial${i}" -name "*.pyc" -delete 2>/dev/null || true
        sudo find "${root}/${method}/trial${i}" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        sudo chown -R "$(id -u):$(id -g)" "${root}/${method}/trial${i}" 2>/dev/null || true
        
        # Calculate and display size
        size=$(du -sh "${root}/${method}/trial${i}/out" 2>/dev/null | awk '{print $1}')
        if [ -n "$size" ]; then
          printf "\033[1;32mDone\033[0m (size: %s)\n" "$size"
        else
          printf "\033[1;31mFailed\033[0m\n"
        fi
      done
    done
  done
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

if [ "$COMMAND" = "stat_plot" ]; then
  # Activate venv if it exists
  if [ -f "$ROOT_DIR/../.venv/bin/activate" ]; then
    . "$ROOT_DIR/../.venv/bin/activate"
  fi

  cd "$ROOT_DIR"
  for CVE in "${CVE_LIST[@]}"; do
    root="./artifact/${CVE}"
    python3 scripts/stat_plot.py --root "${root}" --methods base dd cd dual-dd dual-cd --cve "${CVE}"
  done
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

if [ "$COMMAND" = "tte_check" ]; then
  # Activate venv if it exists
  if [ -f "$ROOT_DIR/../.venv/bin/activate" ]; then
    . "$ROOT_DIR/../.venv/bin/activate"
  fi

  cd "$ROOT_DIR"
  for cve in "${CVE_LIST[@]}"; do
    echo "Running TTE_check.py for $cve"
    python3 scripts/TTE_check.py --bench "$cve"
  done
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

if [ "$COMMAND" = "tte_plot" ]; then
  # Activate venv if it exists
  if [ -f "$ROOT_DIR/../.venv/bin/activate" ]; then
    . "$ROOT_DIR/../.venv/bin/activate"
  fi

  cd "$ROOT_DIR"
  for cve in "${CVE_LIST[@]}"; do
    echo "Running TTE_plot.py for $cve"
    python3 scripts/TTE_plot.py --bench "$cve"
  done
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

if [ "$COMMAND" = "ttr" ]; then
  # Activate venv if it exists
  if [ -f "$ROOT_DIR/../.venv/bin/activate" ]; then
    . "$ROOT_DIR/../.venv/bin/activate"
  fi

  cd "$ROOT_DIR"
  trial=(1 2 3 4 5)
  methods=("base" "dd" "cd" "dual-dd" "dual-cd")
  suffixes=("afl-base" "afl-dd" "afl-cd" "afl-dual-dd" "afl-dual-cd")
  for CVE in "${CVE_LIST[@]}"; do
    root="./artifact/${CVE}"
    mkdir -p "${root}"
    for i in "${trial[@]}"; do
      for idx in "${!methods[@]}"; do
        method="${methods[$idx]}"
        suffix="${suffixes[$idx]}"
        mkdir -p "${root}/${method}/trial${i}"
        printf "Copying TTR logs from %-55s... " "${CVE}-${suffix}-${i}"
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_blocks_hit.txt" "${root}/${method}/trial${i}/" 2>/dev/null || true
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_target_reached.txt" "${root}/${method}/trial${i}/" 2>/dev/null || true
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_block_mapping.txt" "${root}/${method}/trial${i}/" 2>/dev/null || true
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_compile_info.txt" "${root}/${method}/trial${i}/" 2>/dev/null || true
        if [ "$(docker inspect -f '{{.State.Running}}' "${CVE}-${suffix}-${i}" 2>/dev/null)" = "true" ]; then
          docker exec "${CVE}-${suffix}-${i}" tar -cf - -C /workspace out --exclude=".cur_input" --exclude="*.pyc" --exclude="__pycache__" 2>/dev/null | tar -xf - -C "${root}/${method}/trial${i}/" 2>/dev/null || true
        else
          docker cp "${CVE}-${suffix}-${i}:/workspace/out" "${root}/${method}/trial${i}/" 2>/dev/null || true
        fi
        
        # Calculate and display size
        size=$(du -sh "${root}/${method}/trial${i}/out" 2>/dev/null | awk '{print $1}')
        if [ -n "$size" ]; then
          printf "\033[1;32mDone\033[0m (size: %s)\n" "$size"
        else
          printf "\033[1;31mFailed\033[0m\n"
        fi
      done
    done
    sudo chown -R "$(id -u):$(id -g)" "${root}" 2>/dev/null || true
    python3 scripts/TTR.py --root "${root}" --methods base dd cd dual-dd dual-cd --cve "${CVE}"
  done
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

# Run action for each CVE
for cve in "${CVE_LIST[@]}"; do
  echo -e "\n\033[1;34m[Docker-Compose]\033[0m \033[1;35m$cve\033[0m >> \033[1;32m$COMMAND ${EXTRA_ARGS[*]}\033[0m"
  
  if [ ! -f "$ROOT_DIR/bench/$cve/compose.yaml" ]; then
    echo "Warning: compose.yaml not found in bench/$cve. Skipping."
    continue
  fi
  
  (
    cd "$ROOT_DIR/bench/$cve" || exit 1
    case "$COMMAND" in
      up)
        docker compose up -d --build "${EXTRA_ARGS[@]}"
        ;;
      down)
        if [ ${#EXTRA_ARGS[@]} -eq 0 ]; then
          docker compose down -v
        else
          docker compose down "${EXTRA_ARGS[@]}"
        fi
        ;;
      build)
        docker compose build "${EXTRA_ARGS[@]}"
        ;;
      status)
        CONTAINERS=$(docker ps -a --filter name="^/${cve}-afl-" --format "{{.Names}}" | sort)
        if [ -z "$CONTAINERS" ]; then
          echo "No containers found for $cve."
        else
          for container in $CONTAINERS; do
            printf "%-55s : " "$container"
            if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ]; then
              # Get fuzzer process PID from inside the container's tmux session
              FUZZER_PID=$(docker exec "$container" bash -c 'SESSION_NAME=$(basename "$TARGET_BIN"); tmux list-panes -t "$SESSION_NAME" -F "#{pane_pid}" 2>/dev/null' | tr -d '\r' | tr -d '\n')
              if [ -n "$FUZZER_PID" ] && ps -p "$FUZZER_PID" -o cmd= 2>/dev/null | grep -q "afl-fuzz"; then
                core_num=$(grep "Cpus_allowed_list:" "/proc/$FUZZER_PID/status" 2>/dev/null | awk '{print $2}' | tr -d '\r' | tr -d '\n')
                if [ -n "$core_num" ]; then
                  core_info="core: $core_num"
                else
                  core_info="core: unknown"
                fi
                printf "\033[1;32mActive (%s)\033[0m" "$core_info"
                
                # Fetch fuzzer stats
                stats_content=$(docker exec "$container" bash -c 'cat /workspace/out/$FUZZER_NAME/fuzzer_stats 2>/dev/null')
                if [ -n "$stats_content" ]; then
                  bitmap_cvg=$(echo "$stats_content" | grep "^bitmap_cvg" | awk -F: '{print $2}' | tr -d ' ' | tr -d '\r')
                  saved_crashes=$(echo "$stats_content" | grep "^saved_crashes" | awk -F: '{print $2}' | tr -d ' ' | tr -d '\r')
                  corpus_imported=$(echo "$stats_content" | grep "^corpus_imported" | awk -F: '{print $2}' | tr -d ' ' | tr -d '\r')
                  last_crash=$(echo "$stats_content" | grep "^last_crash" | awk -F: '{print $2}' | tr -d ' ' | tr -d '\r')
                  
                  if [ -n "$last_crash" ] && [ "$last_crash" -gt 0 ] 2>/dev/null; then
                    current_time=$(date +%s)
                    diff=$((current_time - last_crash))
                    if [ $diff -lt 0 ]; then diff=0; fi
                    hours=$((diff / 3600))
                    minutes=$(((diff % 3600) / 60))
                    seconds=$((diff % 60))
                    last_crash_str="${hours}h ${minutes}m ${seconds}s ago"
                  else
                    last_crash_str="none"
                  fi
                  
                  echo -e " | cvg: \033[1;36m$bitmap_cvg\033[0m | crashes: \033[1;31m$saved_crashes\033[0m | imported: \033[1;33m$corpus_imported\033[0m | last crash: \033[1;35m$last_crash_str\033[0m"
                else
                  echo -e " | \033[1;30m(No stats available yet)\033[0m"
                fi
              else
                echo -e "\033[1;31mInactive (Fuzzer process died!)\033[0m"
              fi
            else
              echo -e "\033[1;30mStopped (Container not running)\033[0m"
            fi
          done
        fi
        ;;
      log)
        CONTAINERS=$(docker ps -a --filter name="^/${cve}-afl-" --format "{{.Names}}" | sort)
        if [ -z "$CONTAINERS" ]; then
          echo "No containers found for $cve."
        else
          for container in $CONTAINERS; do
            echo -e "\n\033[1;36m>>> Logs for $container:\033[0m"
            docker exec "$container" cat /workspace/cpu_binding.log 2>/dev/null || echo "(Container not running or /workspace/cpu_binding.log not found)"
          done
        fi
        ;;

      *)
        echo "Unknown command: $COMMAND"
        show_usage
        ;;
    esac
  )
done
echo -e "\n\033[1;32mDone.\033[0m"
