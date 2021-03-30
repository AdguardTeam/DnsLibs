cmake_minimum_required(VERSION 3.6)
project(agdns_dnsstamp C CXX)

set(CMAKE_CXX_STANDARD 17)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third-party)
set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if (NOT TARGET libevent)
    add_subdirectory(${THIRD_PARTY_DIR}/libevent ${CMAKE_BINARY_DIR}/libevent)
endif ()

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

add_library(dnsstamp EXCLUDE_FROM_ALL
        include/base64.h
        include/dns_stamp.h
        src/base64.cpp
        src/dns_stamp.cpp)

set_target_properties(dnsstamp PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsstamp PUBLIC include)
target_link_libraries(dnsstamp libevent dnslibs_common)

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnsstamp)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(dns_stamp_test ${TEST_DIR} "" TRUE FALSE)
