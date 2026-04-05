#!/bin/bash
mkdir -p ./plot_results

for instance in $(ls out); do
    if [ -d "out/$instance" ] && [ -f "out/$instance/plot_data" ]; then
        echo "======== Processing instance: $instance ========="
        mkdir -p "./plot_results/$instance"
        afl-plot "out/$instance" "./plot_results/$instance"
    else
        echo "Skipping $instance (No plot_data found)"
    fi
done

echo "All plots generated in ./plot_results/"