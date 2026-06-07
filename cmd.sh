#!/bin/bash

trial=(1 2 3 4 5)
CVE="binutils-2.26_cxxfilt_CVE-2016-4492"
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