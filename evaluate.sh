#!/bin/bash
. ../.venv/bin/activate
# Load CVE list from cves.env (local user config, gitignored)
if [ ! -f "cves.env" ] && [ -f "cves.env.template" ]; then
    cp cves.env.template cves.env
fi

CVE_list=()
if [ -f "cves.env" ]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        clean_line=$(echo "$line" | tr -d '"' | tr -d "'" | tr -d ' ' | tr -d '\r')
        [ -n "$clean_line" ] && CVE_list+=("$clean_line")
    done < "cves.env"
fi

echo "Do you want to run stat_plot? (y/n)"
read answer

if [ "$answer" == "y" ]; then
    trial=(1 2 3 4 5)
    for CVE in ${CVE_list[@]}; do

        root="./artifact/${CVE}"
        mkdir -p ${root}

        methods=("base" "dd" "cd" "dual-dd" "dual-cd")
        suffixes=("afl-base" "afl-dd" "afl-cd" "afl-dual-dd" "afl-dual-cd")

        for i in ${trial[@]}; do
            for idx in ${!methods[@]}; do
                method=${methods[$idx]}
                suffix=${suffixes[$idx]}
                mkdir -p ${root}/${method}/trial${i}
                docker cp ${CVE}-${suffix}-${i}:/workspace/out ${root}/${method}/trial${i}/
                sudo find ${root}/${method}/trial${i} -name "*.pyc" -delete
                sudo find ${root}/${method}/trial${i} -name "__pycache__" -exec rm -rf {} +                
                sudo chown -R $(id -u):$(id -g) ${root}/${method}/trial${i}
            done
        done

        python3 stat_plot.py --root ${root} --methods base dd cd dual-dd dual-cd --cve ${CVE}
    done
fi

echo "Do you want to run TTE_check? (y/n)"
read answer

if [ "$answer" == "y" ]; then
    for cve in ${CVE_list[@]}; do
        echo "Running TTE_check.py for $cve"
        python3 TTE_check.py --bench $cve
    done
fi

echo "Do you want to run TTE_plot? (y/n)"
read answer

if [ "$answer" == "y" ]; then
    for cve in ${CVE_list[@]}; do
        echo "Running TTE_plot.py for $cve"
        python3 TTE_plot.py --bench $cve
    done
fi

echo "Do you want to run TTR? (y/n)"
read answer

if [ "$answer" == "y" ]; then
    trial=(1 2 3 4 5)
    for CVE in ${CVE_list[@]}; do

        root="./artifact/${CVE}"
        mkdir -p ${root}

        methods=("base" "dd" "cd" "dual-dd" "dual-cd")
        suffixes=("afl-base" "afl-dd" "afl-cd" "afl-dual-dd" "afl-dual-cd")

        for i in ${trial[@]}; do
            for idx in ${!methods[@]}; do
                method=${methods[$idx]}
                suffix=${suffixes[$idx]}

                mkdir -p ${root}/${method}/trial${i}

                docker cp ${CVE}-${suffix}-${i}:/workspace/dgf_blocks_hit.txt ${root}/${method}/trial${i}/
                docker cp ${CVE}-${suffix}-${i}:/workspace/dgf_target_reached.txt ${root}/${method}/trial${i}/
                docker cp ${CVE}-${suffix}-${i}:/workspace/dgf_block_mapping.txt ${root}/${method}/trial${i}/
                docker cp ${CVE}-${suffix}-${i}:/workspace/dgf_compile_info.txt ${root}/${method}/trial${i}/
                docker cp ${CVE}-${suffix}-${i}:/workspace/out ${root}/${method}/trial${i}/
            done
        done

        chown -R $(id -u):$(id -g) ${root}
        python3 TTR.py --root ${root} --methods base dd cd dual-dd dual-cd --cve ${CVE}
    done
fi