#!/bin/bash

# Root directory helper
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Dynamic trial number config
export NUM_TRIALS=${NUM_TRIALS:-5}

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
  echo "Usage: $0 {up|down|build|status|log|clean|copy|stat_plot|tte_check|tte_plot|ttr} [cve_name] [-y|--yes|--non-interactive]"
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
  echo "Options:"
  echo "  -y, --yes, --non-interactive : Skip interactive selection and confirmation prompts"
  echo ""
  echo "If [cve_name] is omitted, the command runs on all active CVEs defined in cves.env."
  exit 1
}

is_cve() {
  local arg="$1"
  local active_cves
  active_cves=($(get_cves))
  for cve in "${active_cves[@]}"; do
    if [ "$cve" = "$arg" ]; then
      return 0
    fi
  done
  if [ -d "$ROOT_DIR/bench/$arg" ]; then
    return 0
  fi
  return 1
}

get_active_trial_name() {
  local CVE="$1"
  local container_name="${CVE}-afl-base-1"
  local trial_name=""
  
  if [ "$(docker ps -a -q -f name="^/${container_name}$")" ]; then
    trial_name=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$container_name" 2>/dev/null | grep '^TRIAL_NAME=' | cut -d= -f2 | tr -d '\r' | tr -d '\n')
  fi
  
  if [ -z "$trial_name" ]; then
    if [ -f "$ROOT_DIR/bench/${CVE}/.current_session" ]; then
      trial_name=$(grep '^TRIAL_NAME=' "$ROOT_DIR/bench/${CVE}/.current_session" | cut -d= -f2 | tr -d '\r' | tr -d '\n')
    fi
  fi
  
  if [ -z "$trial_name" ] && [ -d "$ROOT_DIR/artifact/${CVE}" ]; then
    trial_name=$(find "$ROOT_DIR/artifact/${CVE}" -maxdepth 1 -mindepth 1 -type d ! -name "plot" ! -name "TTE_check" -printf "%T@ %p\n" 2>/dev/null | sort -n | tail -1 | awk '{print $2}' | xargs basename 2>/dev/null | sed -E -e 's/_[0-9]{8}_[0-9]{6}$//g' -e 's/_[0-9]{8}_[0-9]{6}_trial[0-9]+$//g' -e 's/_trial[0-9]+$//g' | uniq)
  fi
  
  if [ -z "$trial_name" ]; then
    trial_name="trial_default"
  fi
  
  echo "$trial_name"
}

RUN_ALL=false
NON_INTERACTIVE=false
COMMAND=""
TARGET_CVE=""
TRIAL_NAME=""
EXTRA_ARGS=()

for arg in "$@"; do
  # Convert arg to lowercase to accept case-insensitive commands
  arg_lower=$(echo "$arg" | tr '[:upper:]' '[:lower:]')
  if [[ "$arg_lower" == "--all" ]]; then
    RUN_ALL=true
  elif [[ "$arg_lower" == "-y" || "$arg_lower" == "--yes" || "$arg_lower" == "--non-interactive" ]]; then
    NON_INTERACTIVE=true
  elif [ -z "$COMMAND" ] && [[ "$arg_lower" =~ ^(up|down|build|status|log|clean|copy|stat_plot|tte_check|tte_plot|ttr)$ ]]; then
    COMMAND="$arg_lower"
  elif [[ "$arg" =~ ^[0-9]+$ ]]; then
    export NUM_TRIALS="$arg"
  elif [[ "$arg" == -* ]]; then
    EXTRA_ARGS+=("$arg")
  else
    if is_cve "$arg"; then
      TARGET_CVE="$arg"
    else
      TRIAL_NAME="$arg"
    fi
  fi
done

if [ -z "$COMMAND" ]; then
  echo "Error: Command (up, down, build, status, log, clean, copy, stat_plot, tte_check, tte_plot, ttr) is required."
  show_usage
fi

# Determine target CVEs
if [ "$COMMAND" = "down" ]; then
  if [ "$NON_INTERACTIVE" = "true" ] && [ -n "$TARGET_CVE" ]; then
    CVE_LIST=("$TARGET_CVE")
  else
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
  fi
elif [ "$COMMAND" = "up" ]; then
  if [ "$NON_INTERACTIVE" = "true" ] && [ -n "$TARGET_CVE" ]; then
    CVE_LIST=("$TARGET_CVE")
  else
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
  fi
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
  trial=($(seq 1 $NUM_TRIALS))
  methods=("base" "dd" "cd" "dual-dd" "dual-cd")
  suffixes=("afl-base" "afl-dd" "afl-cd" "afl-dual-dd" "afl-dual-cd")
  for CVE in "${CVE_LIST[@]}"; do
    container_name="${CVE}-afl-base-1"
    if [ ! "$(docker ps -a -q -f name="^/${container_name}$")" ]; then
      container_name="${CVE}-afl-dd-1"
    fi
    session_id=""
    trial_name=""
    
    if [ "$(docker ps -a -q -f name="^/${container_name}$")" ]; then
      session_id=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$container_name" 2>/dev/null | grep '^SESSION_ID=' | cut -d= -f2 | tr -d '\r' | tr -d '\n')
      trial_name=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$container_name" 2>/dev/null | grep '^TRIAL_NAME=' | cut -d= -f2 | tr -d '\r' | tr -d '\n')
    fi
    
    if [ -z "$session_id" ] || [ -z "$trial_name" ]; then
      if [ -f "$ROOT_DIR/bench/${CVE}/.current_session" ]; then
        session_id=$(grep '^SESSION_ID=' "$ROOT_DIR/bench/${CVE}/.current_session" | cut -d= -f2 | tr -d '\r' | tr -d '\n')
        trial_name=$(grep '^TRIAL_NAME=' "$ROOT_DIR/bench/${CVE}/.current_session" | cut -d= -f2 | tr -d '\r' | tr -d '\n')
      fi
    fi
    
    if [ -z "$trial_name" ]; then
      trial_name="trial_$(date +%Y%m%d_%H%M%S)"
    fi
    if [ -z "$session_id" ]; then
      session_id="session_$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [ -d "./artifact/${CVE}/${trial_name}" ]; then
      exist_session_id=""
      if [ -f "./artifact/${CVE}/${trial_name}/.session_id" ]; then
        exist_session_id=$(cat "./artifact/${CVE}/${trial_name}/.session_id" | tr -d '\r' | tr -d '\n')
      fi
      if [ "$exist_session_id" != "$session_id" ]; then
        trial_name="${trial_name}_$(date +%Y%m%d_%H%M%S)"
      fi
    fi
    
    echo -e "Copying results for trial run: \033[1;35m${trial_name}\033[0m"

    mkdir -p "./artifact/${CVE}/${trial_name}"
    echo "$session_id" > "./artifact/${CVE}/${trial_name}/.session_id"

    for idx in "${!methods[@]}"; do
      method="${methods[$idx]}"
      suffix="${suffixes[$idx]}"
      
      for i in "${trial[@]}"; do
        if [ -z "$(docker ps -a -q -f name="^/${CVE}-${suffix}-${i}$")" ]; then
          continue
        fi
        target_dir="./artifact/${CVE}/${trial_name}/${method}/trial${i}"
        mkdir -p "${target_dir}"
        printf "Copying results from %-55s... " "${CVE}-${suffix}-${i}"
        if [ "$(docker inspect -f '{{.State.Running}}' "${CVE}-${suffix}-${i}" 2>/dev/null)" = "true" ]; then
          docker exec "${CVE}-${suffix}-${i}" tar -cf - -C /workspace out --exclude=".cur_input" --exclude="*.pyc" --exclude="__pycache__" 2>/dev/null | tar -xf - -C "${target_dir}/" 2>/dev/null || true
        else
          docker cp "${CVE}-${suffix}-${i}:/workspace/out" "${target_dir}/" 2>/dev/null || true
        fi
        sudo find "${target_dir}" -name "*.pyc" -delete 2>/dev/null || true
        sudo find "${target_dir}" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        sudo chown -R "$(id -u):$(id -g)" "${target_dir}" 2>/dev/null || true
        
        # Calculate and display size
        size=$(du -sh "${target_dir}/out" 2>/dev/null | awk '{print $1}')
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
    trial_name=$(get_active_trial_name "$CVE")
    echo -e "Running stat_plot.py on: \033[1;35m${CVE}\033[0m with trial: \033[1;35m${TRIAL_NAME:-$trial_name}\033[0m"
    python3 scripts/stat_plot.py --root "./artifact/${CVE}" --methods base dd cd dual-dd dual-cd --cve "${CVE}" --trial-name "${TRIAL_NAME:-${trial_name}}"
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
    selected_trial=""
    if [ -n "$TRIAL_NAME" ]; then
      selected_trial="$TRIAL_NAME"
    else
      # Find all available trial directories
      trials=()
      if [ -d "$ROOT_DIR/artifact/$cve" ]; then
        while IFS= read -r d; do
          [ -n "$d" ] && trials+=("$d")
        done < <(find "$ROOT_DIR/artifact/$cve" -maxdepth 1 -mindepth 1 -type d ! -name "plot" ! -name "TTE_check" -exec basename {} \; 2>/dev/null | sort -r)
      fi
      
      if [ ${#trials[@]} -eq 0 ]; then
        selected_trial=$(get_active_trial_name "$cve")
      elif [ ${#trials[@]} -eq 1 ]; then
        selected_trial="${trials[0]}"
      else
        if [ "$NON_INTERACTIVE" = "true" ]; then
          selected_trial="${trials[0]}"
        else
          echo -e "\nAvailable trials for \033[1;35m$cve\033[0m:"
          for i in "${!trials[@]}"; do
            echo "$((i+1)). ${trials[$i]}"
          done
          read -p "Select a trial (1-${#trials[@]}, default 1: ${trials[0]}): " selection
          if [ -z "$selection" ]; then
            selected_trial="${trials[0]}"
          elif [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#trials[@]}" ]; then
            selected_trial="${trials[$((selection-1))]}"
          else
            echo "Error: Invalid selection. Using default: ${trials[0]}"
            selected_trial="${trials[0]}"
          fi
        fi
      fi
    fi
    echo -e "Running TTE_check.py for $cve with trial: \033[1;35m$selected_trial\033[0m"
    python3 scripts/TTE_check.py --bench "$cve" --trial-name "$selected_trial"
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
    echo -e "Running TTE_plot.py for $cve with trial: \033[1;35m${TRIAL_NAME:-all}\033[0m"
    python3 scripts/TTE_plot.py --bench "$cve" --trial-name "${TRIAL_NAME:-all}"
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
  trial=($(seq 1 $NUM_TRIALS))
  methods=("base" "dd" "cd" "dual-dd" "dual-cd")
  suffixes=("afl-base" "afl-dd" "afl-cd" "afl-dual-dd" "afl-dual-cd")
  for CVE in "${CVE_LIST[@]}"; do
    container_name="${CVE}-afl-base-1"
    if [ ! "$(docker ps -a -q -f name="^/${container_name}$")" ]; then
      container_name="${CVE}-afl-dd-1"
    fi
    session_id=""
    trial_name=""
    
    if [ "$(docker ps -a -q -f name="^/${container_name}$")" ]; then
      session_id=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$container_name" 2>/dev/null | grep '^SESSION_ID=' | cut -d= -f2 | tr -d '\r' | tr -d '\n')
      trial_name=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$container_name" 2>/dev/null | grep '^TRIAL_NAME=' | cut -d= -f2 | tr -d '\r' | tr -d '\n')
    fi
    
    if [ -z "$session_id" ] || [ -z "$trial_name" ]; then
      if [ -f "$ROOT_DIR/bench/${CVE}/.current_session" ]; then
        session_id=$(grep '^SESSION_ID=' "$ROOT_DIR/bench/${CVE}/.current_session" | cut -d= -f2 | tr -d '\r' | tr -d '\n')
        trial_name=$(grep '^TRIAL_NAME=' "$ROOT_DIR/bench/${CVE}/.current_session" | cut -d= -f2 | tr -d '\r' | tr -d '\n')
      fi
    fi
    
    if [ -z "$trial_name" ]; then
      trial_name="trial_$(date +%Y%m%d_%H%M%S)"
    fi
    if [ -z "$session_id" ]; then
      session_id="session_$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [ -d "./artifact/${CVE}/${trial_name}" ]; then
      exist_session_id=""
      if [ -f "./artifact/${CVE}/${trial_name}/.session_id" ]; then
        exist_session_id=$(cat "./artifact/${CVE}/${trial_name}/.session_id" | tr -d '\r' | tr -d '\n')
      fi
      if [ "$exist_session_id" != "$session_id" ]; then
        trial_name="${trial_name}_$(date +%Y%m%d_%H%M%S)"
      fi
    fi
    
    echo -e "Copying TTR logs for trial run: \033[1;35m${trial_name}\033[0m"

    mkdir -p "./artifact/${CVE}/${trial_name}"
    echo "$session_id" > "./artifact/${CVE}/${trial_name}/.session_id"

    for idx in "${!methods[@]}"; do
      method="${methods[$idx]}"
      suffix="${suffixes[$idx]}"
      
      for i in "${trial[@]}"; do
        if [ -z "$(docker ps -a -q -f name="^/${CVE}-${suffix}-${i}$")" ]; then
          continue
        fi
        target_dir="./artifact/${CVE}/${trial_name}/${method}/trial${i}"
        mkdir -p "${target_dir}"
        printf "Copying TTR logs from %-55s... " "${CVE}-${suffix}-${i}"
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_blocks_hit.txt" "${target_dir}/" 2>/dev/null 2>&1 || true
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_target_reached.txt" "${target_dir}/" >/dev/null 2>&1 || true
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_block_mapping.txt" "${target_dir}/" >/dev/null 2>&1 || true
        docker cp "${CVE}-${suffix}-${i}:/workspace/dgf_compile_info.txt" "${target_dir}/" >/dev/null 2>&1 || true
        if [[ "$suffix" == "afl-base" || "$suffix" == "afl-cd" || "$suffix" == "afl-dd" ]]; then
          docker cp "${CVE}-${suffix}-slave-${i}:/workspace/dgf_blocks_hit.txt" "${target_dir}/dgf_blocks_hit_slave.txt" >/dev/null 2>&1 || true
          docker cp "${CVE}-${suffix}-slave-${i}:/workspace/dgf_target_reached.txt" "${target_dir}/dgf_target_reached_slave.txt" >/dev/null 2>&1 || true
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "${CVE}-${suffix}-${i}" 2>/dev/null)" = "true" ]; then
          docker exec "${CVE}-${suffix}-${i}" tar -cf - -C /workspace out --exclude=".cur_input" --exclude="*.pyc" --exclude="__pycache__" 2>/dev/null | tar -xf - -C "${target_dir}/" 2>/dev/null || true
        else
          docker cp "${CVE}-${suffix}-${i}:/workspace/out" "${target_dir}/" 2>/dev/null || true
        fi
        
        # Calculate and display size
        size=$(du -sh "${target_dir}/out" 2>/dev/null | awk '{print $1}')
        if [ -n "$size" ]; then
          printf "\033[1;32mDone\033[0m (size: %s)\n" "$size"
        else
          printf "\033[1;31mFailed\033[0m\n"
        fi
      done
    done
    sudo chown -R "$(id -u):$(id -g)" "./artifact/${CVE}/${trial_name}" 2>/dev/null || true
    python3 scripts/TTR.py --root "./artifact/${CVE}" --methods base dd cd dual-dd dual-cd --cve "${CVE}" --trial-name "${TRIAL_NAME:-${trial_name}}"
  done
  echo -e "\n\033[1;32mDone.\033[0m"
  exit 0
fi

# Run action for each CVE
for cve in "${CVE_LIST[@]}"; do
  echo -e "\n\033[1;34m[Docker-Compose]\033[0m \033[1;35m$cve\033[0m >> \033[1;32m$COMMAND ${EXTRA_ARGS[*]}\033[0m"
  
  if [ "$COMMAND" = "up" ]; then
    active_trial_name="$TRIAL_NAME"
    if [ -z "$active_trial_name" ]; then
      active_trial_name="trial_$(date +%Y%m%d_%H%M%S)"
    fi
    active_session_id="session_$(date +%Y%m%d_%H%M%S)"
    
    mkdir -p "$ROOT_DIR/bench/${cve}"
    echo "SESSION_ID=${active_session_id}" > "$ROOT_DIR/bench/${cve}/.current_session"
    echo "TRIAL_NAME=${active_trial_name}" >> "$ROOT_DIR/bench/${cve}/.current_session"
    
    export SESSION_ID="${active_session_id}"
    export TRIAL_NAME="${active_trial_name}"
    echo -e "Starting run with SESSION_ID=\033[1;36m$SESSION_ID\033[0m and TRIAL_NAME=\033[1;35m$TRIAL_NAME\033[0m"
  else
    if [ -f "$ROOT_DIR/bench/${cve}/.current_session" ]; then
      export SESSION_ID=$(grep '^SESSION_ID=' "$ROOT_DIR/bench/${cve}/.current_session" | cut -d= -f2)
      export TRIAL_NAME=$(grep '^TRIAL_NAME=' "$ROOT_DIR/bench/${cve}/.current_session" | cut -d= -f2)
    fi
    export SESSION_ID=${SESSION_ID:-dummy_session}
    export TRIAL_NAME=${TRIAL_NAME:-dummy_trial}
  fi

  # Auto-generate docker-compose.master.yml before executing docker compose commands
  python3 "$ROOT_DIR/scripts/generate_master_compose.py" "$NUM_TRIALS"

  if [ ! -f "$ROOT_DIR/bench/$cve/compose.yaml" ]; then
    echo "Warning: compose.yaml not found in bench/$cve. Skipping."
    continue
  fi
  
  (
    cd "$ROOT_DIR/bench/$cve" || exit 1
    case "$COMMAND" in
      up)
        SERVICES=()
        for i in $(seq 1 $NUM_TRIALS); do
          if [ "$RUN_ALL" = "true" ]; then
            SERVICES+=("afl-base-$i" "afl-base-slave-$i" "afl-cd-$i" "afl-cd-slave-$i")
          fi
          SERVICES+=("afl-dd-$i" "afl-dd-slave-$i" "afl-dual-dd-$i" "afl-dual-cd-$i")
        done
        docker compose up -d --build "${EXTRA_ARGS[@]}" "${SERVICES[@]}"
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
