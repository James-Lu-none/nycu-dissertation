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
  echo "Usage: $0 {up|down|build|status} [cve_name]"
  echo "Commands:"
  echo "  up      : Start docker containers for CVE trials"
  echo "  down    : Stop docker containers and remove named volumes (-v)"
  echo "  build   : Build docker images for CVE trials"
  echo "  status  : Show container running status"
  echo ""
  echo "If [cve_name] is omitted, the command runs on all active CVEs defined in cves.env."
  exit 1
}

COMMAND=""
TARGET_CVE=""
EXTRA_ARGS=()

for arg in "$@"; do
  if [ -z "$COMMAND" ] && [[ "$arg" =~ ^(up|down|build|status)$ ]]; then
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

if [ ${#CVE_LIST[@]} -eq 0 ]; then
  echo "No active CVEs found to manage."
  exit 0
fi

# Run action for each CVE
for cve in "${CVE_LIST[@]}"; do
  echo "================================================================================"
  echo " CVE: $cve"
  echo " Action: $COMMAND ${EXTRA_ARGS[*]}"
  echo "================================================================================"
  
  if [ ! -f "$ROOT_DIR/bench/$cve/compose.yaml" ]; then
    echo "Warning: compose.yaml not found in bench/$cve. Skipping."
    continue
  fi
  
  (
    cd "$ROOT_DIR/bench/$cve" || exit 1
    case "$COMMAND" in
      up)
        docker compose up -d "${EXTRA_ARGS[@]}"
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
      *)
        echo "Unknown command: $COMMAND"
        show_usage
        ;;
    esac
  )
done
echo "================================================================================"
echo "Done."
