#!/bin/bash
# recursive search for plot_data file
RESULTS_ROOT="."
PLOT_DATA_FILES=$(find "$RESULTS_ROOT" -type f -name "plot_data")
OUTPUT_DIR="$RESULTS_ROOT/plot_results"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

for file in $PLOT_DATA_FILES; do
    echo "======== Processing $(dirname "$file") ========="
    output_dir="$OUTPUT_DIR/$(dirname "$file")"
    mkdir -p "$output_dir"
    afl-plot "$(dirname "$file")" "$output_dir"
    # copy fuzzer_stats file if exists
    if [ -f "$(dirname "$file")/fuzzer_stats" ]; then
        echo "Copying fuzzer_stats from $(dirname "$file") to $output_dir"
        cp "$(dirname "$file")/fuzzer_stats" "$output_dir/"
        chmod 666 "$output_dir/fuzzer_stats"
    fi
done