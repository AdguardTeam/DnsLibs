cmake_minimum_required(VERSION 3.24)
if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "cmake/conan_bootstrap.cmake")
endif()
project(agdns C CXX)

# Force the static MSVC runtime (/MT) for this project on Windows so its object
# files match the Conan-installed dependencies, which are built with the static
# CRT (compiler.runtime=static and /MT in the Conan profile / toolchain shipped
# with the NativeLibsCommon conanfiles — downloaded at configure time by
# cmake/conan_bootstrap.cmake into the build tree's conan/ directory, not
# checked into this repo). Without this the project compiles with CMake's
# default /MD (dynamic CRT) and the link fails with LNK2038 RuntimeLibrary
# mismatches against ssl.lib, fmt.lib, ag_common.lib etc. The CMake-Conan
# provider only mirrors the project's MSVC runtime into the Conan profile when
# CMAKE_MSVC_RUNTIME_LIBRARY is explicitly set, so it must be set here (not by
# the provider). platform/windows/capi/CMakeLists.txt does the same for the
# capi DLL build.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
endif()

add_subdirectory(proxy)
add_subdirectory(tools/adyg)

enable_testing()
