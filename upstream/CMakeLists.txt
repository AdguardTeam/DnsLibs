cmake_minimum_required(VERSION 3.6)
project(agdns_upstream C CXX)

set(CMAKE_CXX_STANDARD 17)
cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0079 NEW)

if (NOT TARGET event_core)
    add_subdirectory(../third-party/libevent ${CMAKE_BINARY_DIR}/libevent)
endif ()

if (NOT TARGET ldns)
    add_subdirectory(../third-party/ldns ${CMAKE_BINARY_DIR}/ldns)
endif ()

add_library(upstream EXCLUDE_FROM_ALL
        include/upstream.h
        src/connection_pool.cpp
        src/upstream.cpp
        src/upstream_doh.cpp
        src/upstream_dot.cpp
        src/upstream_plain.cpp
        src/connection_pool.h
        src/upstream_plain.h
        src/socket_address.cpp
        include/socket_address.h
        src/event_loop.cpp
        include/event_loop.h
        include/upstream_util.h
        src/upstream_util.cpp)

target_include_directories(upstream PUBLIC include)
target_link_libraries(upstream libevent ldns)

enable_testing()
if (NOT TARGET tests)
    add_subdirectory(../third-party/googletest googletest)
    add_executable(tests EXCLUDE_FROM_ALL)
    target_link_libraries(tests gtest_main)
    add_test(tests tests)
endif ()

target_sources(tests PRIVATE test/test_upstream.cpp)
target_link_libraries(tests upstream)
