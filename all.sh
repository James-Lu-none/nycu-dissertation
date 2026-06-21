#!/bin/bash
. ../.venv/bin/activate
CVE_list=(
    # libming
    # "libming-4.8.1_swftophp_CVE-2019-9114"
    # "libming-4.8_swftophp_CVE-2018-20427"
    # "libming-4.8_swftophp_CVE-2018-7868"
    # "libming-4.8_swftophp_CVE-2018-8807"
    # "libming-4.8_swftophp_CVE-2018-8962"
    # "libming-4.7_swftophp_CVE-2017-9988"
    # "libming-4.7_swftophp_CVE-2017-11728"
    # "libming-4.8_swftophp_CVE-2018-11225"
    # "libming-4.8_swftophp_CVE-2018-11226"
    # "libming-4.8_swftophp_CVE-2019-12982"
    # "libming-4.8_swftophp_CVE-2020-6628"
    # binutils
    # "binutils-2.28_objdump_CVE-2017-8396"
    # "binutils-2.29_nm_CVE-2017-14940"
    # "binutils-2.26_cxxfilt_CVE-2016-6131"
    # "binutils-2.26_cxxfilt_CVE-2016-4492"
    # "binutils-2.26_cxxfilt_CVE-2016-4491"
    # "binutils-2.31.1_objdump_CVE-2018-17360"
    # lrzip
    # "lrzip-9de7ccb_lrzip_CVE-2017-8846"
    # libjpeg
    # "libjpeg-2.0.4_cjpeg_CVE-2020-13790"
    # "libjpeg-1.5.90_cjpeg_CVE-2018-14498"
    # libxml2
    # "libxml2-2.9.4_xmllint_CVE-2017-9047"
    # "libxml2-2.9.4_xmllint_CVE-2017-9048"
)

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