cmake_minimum_required(VERSION 3.6)
project(agdns_dnsstamp C CXX)
include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.txt" SCOPE_NAME agdns)

set(CMAKE_CXX_STANDARD 17)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

add_library(dnsstamp EXCLUDE_FROM_ALL
        include/dns_stamp.h
        src/dns_stamp.cpp)

set_target_properties(dnsstamp PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsstamp PUBLIC include)
target_link_libraries(dnsstamp CONAN_PKG::libevent dnslibs_common)

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnsstamp)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(dns_stamp_test ${TEST_DIR} "" TRUE FALSE)
