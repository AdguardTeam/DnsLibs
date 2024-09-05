cmake_minimum_required(VERSION 3.24)
if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "cmake/conan_bootstrap.cmake")
endif()
project(agdns C CXX)

add_subdirectory(proxy)

enable_testing()
