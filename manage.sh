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
  echo "Usage: $0 {up|down|build|status|log|clean} [cve_name]"
  echo "Commands:"
  echo "  up      : Start docker containers for CVE trials"
  echo "  down    : Stop docker containers and remove named volumes (-v)"
  echo "  build   : Build docker images for CVE trials"
  echo "  status  : Show container running status"
  echo "  log     : Print /workspace/cpu_binding.log from inside containers"
  echo "  clean   : Force stop and remove containers, volumes, and images"
  echo ""
  echo "If [cve_name] is omitted, the command runs on all active CVEs defined in cves.env."
  exit 1
}

COMMAND=""
TARGET_CVE=""
EXTRA_ARGS=()

for arg in "$@"; do
  if [ -z "$COMMAND" ] && [[ "$arg" =~ ^(up|down|build|status|log|clean)$ ]]; then
    COMMAND="$arg"
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
  echo "Error: Command (up, down, build, status) is required."
  show_usage
fi

# Determine target CVEs
if [ -n "$TARGET_CVE" ]; then
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
        docker compose ps "${EXTRA_ARGS[@]}"
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
