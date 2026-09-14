cmake_minimum_required(VERSION 3.20)
project(enigma_linux_desktop LANGUAGES CXX)

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets)

add_library(enigma_linux_interop STATIC
    src/enigma_core.cpp
)

target_compile_features(enigma_linux_interop PUBLIC cxx_std_20)
target_include_directories(enigma_linux_interop
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_executable(enigma_linux_desktop
    src/main.cpp
)
target_compile_features(enigma_linux_desktop PRIVATE cxx_std_20)
target_link_libraries(enigma_linux_desktop
    PRIVATE
        Qt6::Widgets
        enigma_linux_interop
)

if(MSVC)
    target_compile_options(enigma_linux_interop PRIVATE /W4 /WX)
    target_compile_options(enigma_linux_desktop PRIVATE /W4 /WX)
else()
    target_compile_options(enigma_linux_interop PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(enigma_linux_desktop PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
