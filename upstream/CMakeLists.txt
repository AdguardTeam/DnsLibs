cmake_minimum_required(VERSION 3.6)
project(agdns_upstream C CXX)

set(CMAKE_CXX_STANDARD 17)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third-party)

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

if (NOT TARGET libevent)
    add_subdirectory(${THIRD_PARTY_DIR}/libevent ${CMAKE_BINARY_DIR}/libevent)
endif ()

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/ldns)
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
target_link_libraries(upstream dnslibs_common libevent ldns)

enable_testing()
if (NOT TARGET tests)
    add_subdirectory(${THIRD_PAcRTY_DIR}/googletest ${CMAKE_BINARY_DIR}/googletest)
    add_custom_target(tests)
endif ()

link_libraries(gtest gtest_main upstream)

add_executable(upstream_test EXCLUDE_FROM_ALL test/test_upstream.cpp)
add_test(upstream_test upstream_test)
add_dependencies(tests upstream_test)
