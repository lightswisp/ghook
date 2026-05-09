cmake_minimum_required(VERSION 3.16)

project(example LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(GHOOK_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../build/libghook.a)

set(SOURCES main.c)

add_library(example SHARED ${SOURCES})

# Include headers from the static library
target_include_directories(example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# Link against the static library (.a)
target_link_libraries(example PRIVATE ${GHOOK_LIB})

target_compile_options(example PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)
