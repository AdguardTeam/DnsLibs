cmake_minimum_required(VERSION 3.24)
project(agdns_dnsstamp C CXX)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

add_library(dnsstamp EXCLUDE_FROM_ALL
        include/dns/dnsstamp/dns_stamp.h
        dns_stamp.cpp)

find_package(libevent REQUIRED)
find_package(ada REQUIRED)

set_target_properties(dnsstamp PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsstamp PUBLIC include)
target_link_libraries(dnsstamp libevent::libevent dnslibs_common ada::ada)

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnsstamp)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(dns_stamp_test ${TEST_DIR} "" TRUE FALSE)
