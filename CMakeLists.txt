cmake_minimum_required(VERSION 3.16)

project(ghook LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SOURCES src/ghook.c)

add_library(ghook STATIC ${SOURCES})

target_include_directories(ghook
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(ghook PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_compile_options(ghook PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)
