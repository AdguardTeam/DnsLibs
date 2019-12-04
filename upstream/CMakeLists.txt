cmake_minimum_required(VERSION 3.6)
project(agdns_upstream C CXX)

set(CMAKE_CXX_STANDARD 17)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third-party)
set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_library(upstream EXCLUDE_FROM_ALL
        include/upstream.h
        src/upstream.cpp
        src/upstream_doh.cpp
        src/upstream_dot.cpp
        src/upstream_plain.cpp
        src/upstream_plain.h
        src/event_loop.cpp
        include/event_loop.h
        src/connection.cpp
        src/connection.h src/upstream_dot.h src/dns_framed.cpp src/dns_framed.h src/bootstrapper.cpp src/bootstrapper.h
        src/upstream_dnscrypt.cpp
        src/upstream_dnscrypt.h)

set_target_properties(upstream PROPERTIES POSITION_INDEPENDENT_CODE ON)

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

if (NOT TARGET agdns_dnsstamp)
    add_subdirectory(${DNSLIBS_DIR}/dnsstamp ${CMAKE_BINARY_DIR}/dnsstamp)
endif ()

if (NOT TARGET agdns_dnscrypt)
    add_subdirectory(${DNSLIBS_DIR}/dnscrypt ${CMAKE_BINARY_DIR}/dnscrypt)
endif ()

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

if (NOT TARGET libevent)
    add_subdirectory(${THIRD_PARTY_DIR}/libevent ${CMAKE_BINARY_DIR}/third-party/libevent)
endif ()

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/third-party/ldns)
endif ()

if (NOT TARGET libcurl)
    add_subdirectory(${THIRD_PARTY_DIR}/curl ${CMAKE_BINARY_DIR}/third-party/curl)
endif ()

target_include_directories(upstream PUBLIC include)
target_include_directories(upstream PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(upstream dnslibs_common dnsstamp dnscrypt)
target_link_libraries(upstream boringssl_static libevent ldns libcurl)

enable_testing()
if (NOT TARGET tests)
    add_subdirectory(${THIRD_PARTY_DIR}/googletest ${CMAKE_BINARY_DIR}/googletest)
    add_custom_target(tests)
endif ()

link_libraries(gtest gtest_main upstream)

add_executable(upstream_test EXCLUDE_FROM_ALL test/test_upstream.cpp)
add_test(upstream_test upstream_test)
add_dependencies(tests upstream_test)
