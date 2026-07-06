#!/bin/bash
USE_SLURM=0
NEW_ARGS=()

for arg in "$@"; do
    if [ "$arg" == "--slurm" ]; then
        USE_SLURM=1
    else
        NEW_ARGS+=("$arg")
    fi
done

if [ "$USE_SLURM" -eq 1 ]; then
    exec python3 "$(dirname "$0")/manage_slurm.py" "${NEW_ARGS[@]}"
else
    exec python3 "$(dirname "$0")/manage.py" "$@"
fi
