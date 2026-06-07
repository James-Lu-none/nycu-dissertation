原論文 under performed 或 N.A. 的 (在40個trial中成功達到目標的次數沒有超過一半):
libming-4.8_swftophp_CVE-2018-20427 (比較慢): 可編譯、可找到target、已跑24小時
libming-4.8.1_swftophp_CVE-2019-9114: (比較慢) 可編譯、可找到target、已跑24小時 
binutils-2.28_objdump_CVE-2017-8396 (0): 找不到target: libbfd.c:615
binutils-2.29_nm_CVE-2017-14940 (6): 可編譯、可找到target、已跑24小時, 但只能到達兩個 control dependents

libming-4.8_swftophp_CVE-2018-7868 (13): 可編譯、可找到target、執行fuzzing中
binutils-2.26_cxxfilt_CVE-2016-4491 (6): 可編譯、可找到target (找不到target、將trace中第二行作為後target後)
binutils-2.26_cxxfilt_CVE-2016-6131 (0): 可編譯、可找到target、執行fuzzing中

libming-4.8_swftophp_CVE-2018-8807 (1): 可編譯、可找到target、執行fuzzing中
libming-4.8_swftophp_CVE-2018-8962 (4): 可編譯、可找到target、執行fuzzing中
lrzip-9de7ccb_lrzip_CVE-2017-8846 (0): 可編譯、可找到target
binutils-2.31.1_objdump_CVE-2018-17360 (6): 有找到target但 control dependents 是空的
libjpeg-2.0.4_cjpeg_CVE-2020-13790 (10): 可編譯、但只找到2個 control dependents