cmake_minimum_required(VERSION 3.20)
project(enigma_linux_interop LANGUAGES CXX)

add_library(enigma_linux_interop STATIC
    src/enigma_core.cpp
)

target_compile_features(enigma_linux_interop PUBLIC cxx_std_20)
target_include_directories(enigma_linux_interop
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

if(MSVC)
    target_compile_options(enigma_linux_interop PRIVATE /W4 /WX)
else()
    target_compile_options(enigma_linux_interop PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
