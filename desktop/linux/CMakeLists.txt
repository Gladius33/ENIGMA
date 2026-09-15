cmake_minimum_required(VERSION 3.20)
project(enigma_linux_desktop VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets)
set(CMAKE_AUTORCC ON)

set(ENIGMA_CORE_LIBRARY "" CACHE FILEPATH "Path to the compiled ENIGMA Rust core shared library")
if(NOT ENIGMA_CORE_LIBRARY)
    message(FATAL_ERROR "ENIGMA_CORE_LIBRARY must point to the compiled Rust enigma_core shared library")
endif()

add_library(enigma_core_native SHARED IMPORTED GLOBAL)
set_target_properties(enigma_core_native PROPERTIES
    IMPORTED_LOCATION "${ENIGMA_CORE_LIBRARY}"
)

add_library(enigma_linux_interop STATIC
    src/enigma_core.cpp
)

target_compile_features(enigma_linux_interop PUBLIC cxx_std_20)
target_include_directories(enigma_linux_interop
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
target_link_libraries(enigma_linux_interop
    PUBLIC
        enigma_core_native
)

add_executable(enigma_linux_desktop
    src/main.cpp
    enigma_resources.qrc
)
target_compile_features(enigma_linux_desktop PRIVATE cxx_std_20)
target_include_directories(enigma_linux_desktop
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../design
)
target_link_libraries(enigma_linux_desktop
    PRIVATE
        Qt6::Widgets
        enigma_linux_interop
)

set_target_properties(enigma_linux_desktop PROPERTIES
    INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}/enigma"
)

install(
    TARGETS enigma_linux_desktop
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(
    FILES "${ENIGMA_CORE_LIBRARY}"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/enigma"
)
install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../android/app/src/main/res/drawable-nodpi/enigma_logo.png"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/512x512/apps"
    RENAME enigma.png
)
install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/enigma.desktop"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/applications"
)

set(CPACK_PACKAGE_NAME "enigma-desktop")
set(CPACK_PACKAGE_VENDOR "ENIGMA")
set(CPACK_PACKAGE_CONTACT "ENIGMA")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ENIGMA end-to-end encrypted desktop messenger")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ENIGMA")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)

if(MSVC)
    target_compile_options(enigma_linux_interop PRIVATE /W4 /WX)
    target_compile_options(enigma_linux_desktop PRIVATE /W4 /WX)
else()
    target_compile_options(enigma_linux_interop PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(enigma_linux_desktop PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
