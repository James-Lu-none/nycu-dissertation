#!/bin/bash

trial=(1 2 3)
CVE="CVE-2018-20427"
root="./artifact/${CVE}"
mkdir -p ${root}
rm -rf ${root}/*

baseline="swftophp-afl-origin"
icd="swftophp-afl-icd"

for i in ${trial[@]}; do
  
    mkdir -p ${root}/${baseline}/trial${i}
    mkdir -p ${root}/${icd}/trial${i}

    docker cp ${baseline}-${i}:/workspace/dgf_blocks_hit.txt ${root}/${baseline}/trial${i}/
    docker cp ${baseline}-${i}:/workspace/dgf_target_reached.txt ${root}/${baseline}/trial${i}/
    docker cp ${baseline}-${i}:/workspace/dgf_block_mapping.txt ${root}/${baseline}/trial${i}/
    docker cp ${baseline}-${i}:/workspace/dgf_compile_info.txt ${root}/${baseline}/trial${i}/
    docker cp ${baseline}-${i}:/workspace/out ${root}/${baseline}/trial${i}/

    docker cp ${icd}-${i}:/workspace/dgf_blocks_hit.txt ${root}/${icd}/trial${i}/
    docker cp ${icd}-${i}:/workspace/dgf_target_reached.txt ${root}/${icd}/trial${i}/
    docker cp ${icd}-${i}:/workspace/dgf_block_mapping.txt ${root}/${icd}/trial${i}/
    docker cp ${icd}-${i}:/workspace/dgf_compile_info.txt ${root}/${icd}/trial${i}/
    docker cp ${icd}-${i}:/workspace/out ${root}/${icd}/trial${i}/
done

chown -R $(id -u):$(id -g) ${root}

python3 TTR.py --root ${root} --methods $baseline $icd --trials 1 2 3 --cve ${CVE}
python3 cov.py --root ${root} --methods $baseline $icd --trials 1 2 3 --cve ${CVE}