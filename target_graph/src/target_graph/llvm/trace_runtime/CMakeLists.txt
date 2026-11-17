cmake_minimum_required(VERSION 3.14)
project(target_graph_trace C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(target_graph_trace_static STATIC trace_runtime.c)
set_target_properties(target_graph_trace_static PROPERTIES OUTPUT_NAME "target_graph_trace")

add_library(target_graph_trace_shared SHARED trace_runtime.c)
set_target_properties(target_graph_trace_shared PROPERTIES OUTPUT_NAME "target_graph_trace")

