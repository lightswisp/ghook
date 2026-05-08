cmake_minimum_required(VERSION 3.10)

project(ghook)

add_library(hook SHARED hook.c)

set_target_properties(hook PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_compile_options(hook PRIVATE -ggdb)

set_target_properties(hook PROPERTIES
    OUTPUT_NAME "hook"
)
