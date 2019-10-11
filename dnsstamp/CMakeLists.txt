cmake_minimum_required(VERSION 3.6)
project(agdns_dnsstamp C CXX)

set(CMAKE_CXX_STANDARD 17)
cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0079 NEW)

add_library(dnsstamp EXCLUDE_FROM_ALL
        include/base64.h
        include/dns_stamp.h
        src/base64.cpp
        src/dns_stamp.cpp)

target_include_directories(dnsstamp PUBLIC include)

enable_testing()
if (NOT TARGET tests)
    add_subdirectory(../third-party/googletest googletest)
    add_executable(tests EXCLUDE_FROM_ALL)
    target_link_libraries(tests gtest_main)
    add_test(tests tests)
endif ()

target_sources(tests PRIVATE test/dns_stamp_test.cpp)
target_link_libraries(tests dnsstamp)
