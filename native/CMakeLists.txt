cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

# Native (C++) part of binary-cpp. Builds libbncpp_native.dylib against the BN API checkout whose revision matches
# the installed app (api_REVISION.txt). BN loads native plugins only from the top level of the plugins folder, so
# the dylib gets its own symlink there (CLAUDE.md, Commands).
project(bncpp_native CXX C)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # native/build/compile_commands.json for clangd

find_path(
    BN_API_PATH
    NAMES binaryninjaapi.h
    HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../../binaryninja-api $ENV{BN_API_PATH}
    REQUIRED
)
# Core only for now; a UI part needs HEADLESS=OFF and -DCMAKE_PREFIX_PATH=~/Qt/6.11.1/macos.
set(HEADLESS ON CACHE BOOL "Build without the BN UI API")
add_subdirectory(${BN_API_PATH} api)

add_library(${PROJECT_NAME} SHARED
    src/plugin.cpp)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
