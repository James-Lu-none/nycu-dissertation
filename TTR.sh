#!/bin/bash

CVE_list=(
    # libming
    "libming-4.8.1_swftophp_CVE-2019-9114"
    "libming-4.8_swftophp_CVE-2018-20427"
    "libming-4.8_swftophp_CVE-2018-7868"
    "libming-4.8_swftophp_CVE-2018-8807"
    "libming-4.8_swftophp_CVE-2018-8962"
    # binutils
    "binutils-2.28_objdump_CVE-2017-8396"
    "binutils-2.29_nm_CVE-2017-14940"
    "binutils-2.26_cxxfilt_CVE-2016-6131"
    "binutils-2.26_cxxfilt_CVE-2016-4492"
    "binutils-2.26_cxxfilt_CVE-2016-4491"
    "binutils-2.31.1_objdump_CVE-2018-17360"
    # lrzip
    # "lrzip-9de7ccb_lrzip_CVE-2017-8846"
    # libjpeg
    # "libjpeg-2.0.4_cjpeg_CVE-2020-13790"
)

trial=(1 2 3 4 5)
for CVE in ${CVE_list[@]}; do

    root="./artifact/${CVE}"
    mkdir -p ${root}

    baseline="afl-origin"
    icd="afl-icd"

    for i in ${trial[@]}; do
    
        mkdir -p ${root}/${baseline}/trial${i}
        mkdir -p ${root}/${icd}/trial${i}

        docker cp ${CVE}-${baseline}-${i}:/workspace/dgf_blocks_hit.txt ${root}/${baseline}/trial${i}/
        docker cp ${CVE}-${baseline}-${i}:/workspace/dgf_target_reached.txt ${root}/${baseline}/trial${i}/
        docker cp ${CVE}-${baseline}-${i}:/workspace/dgf_block_mapping.txt ${root}/${baseline}/trial${i}/
        docker cp ${CVE}-${baseline}-${i}:/workspace/dgf_compile_info.txt ${root}/${baseline}/trial${i}/
        docker cp ${CVE}-${baseline}-${i}:/workspace/out ${root}/${baseline}/trial${i}/

        docker cp ${CVE}-${icd}-${i}:/workspace/dgf_blocks_hit.txt ${root}/${icd}/trial${i}/
        docker cp ${CVE}-${icd}-${i}:/workspace/dgf_target_reached.txt ${root}/${icd}/trial${i}/
        docker cp ${CVE}-${icd}-${i}:/workspace/dgf_block_mapping.txt ${root}/${icd}/trial${i}/
        docker cp ${CVE}-${icd}-${i}:/workspace/dgf_compile_info.txt ${root}/${icd}/trial${i}/
        docker cp ${CVE}-${icd}-${i}:/workspace/out ${root}/${icd}/trial${i}/
    done

    chown -R $(id -u):$(id -g) ${root}

    python3 TTR.py --root ${root} --methods $baseline $icd --cve ${CVE}
    python3 cov.py --root ${root} --methods $baseline $icd --cve ${CVE}
done