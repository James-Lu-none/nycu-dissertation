cmake_minimum_required(VERSION 3.10)
project(klee_example C)

# Find LLVM & KLEE
find_package(LLVM REQUIRED CONFIG)
find_package(KLEE REQUIRED)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVM include dir: ${LLVM_INCLUDE_DIRS}")

include_directories(${LLVM_INCLUDE_DIRS} ${KLEE_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS} ${KLEE_LIBRARY_DIRS})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -emit-llvm -c -O0")

add_custom_command(
    OUTPUT test.bc
    COMMAND ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS} ${CMAKE_SOURCE_DIR}/test.c -o test.bc
    DEPENDS test.c
)

add_custom_target(klee_bc ALL DEPENDS test.bc)

