cmake_minimum_required(VERSION 3.14)
project(TargetGraphPass C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

add_library(TargetGraphPass MODULE TargetGraphPass.cpp)
target_compile_definitions(TargetGraphPass PRIVATE ${LLVM_DEFINITIONS})

# Independent instruction-level analysis; legacy pass remains unchanged.
add_library(AnalysisV2Pass MODULE AnalysisV2Pass.cpp)
target_compile_definitions(AnalysisV2Pass PRIVATE ${LLVM_DEFINITIONS})

# Identity bridge only; DG does all slicing in its independent backend.
add_library(DGIdentityPass MODULE DGIdentityPass.cpp)
target_compile_definitions(DGIdentityPass PRIVATE ${LLVM_DEFINITIONS})

add_library(TraceInstrumentPass MODULE TraceInstrumentPass.cpp)
target_compile_definitions(TraceInstrumentPass PRIVATE ${LLVM_DEFINITIONS})
