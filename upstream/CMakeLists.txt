cmake_minimum_required(VERSION 3.6)
project(agdns_upstream C CXX)

set(CMAKE_CXX_STANDARD 17)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third-party)
set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_library(upstream EXCLUDE_FROM_ALL
        src/upstream.cpp
        src/upstream_doh.h src/upstream_doh.cpp
        src/upstream_dot.h src/upstream_dot.cpp
        src/upstream_doq.h src/upstream_doq.cpp
        src/upstream_plain.h src/upstream_plain.cpp
        src/event_loop.cpp
        src/connection.h src/connection.cpp
        src/dns_framed.h src/dns_framed.cpp
        src/bootstrapper.h src/bootstrapper.cpp
        src/upstream_dnscrypt.h src/upstream_dnscrypt.cpp
        src/resolver.h src/resolver.cpp
        src/upstream_utils.cpp
        src/tls_session_cache.cpp
    )

set_target_properties(upstream PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(upstream PRIVATE
        -Wall -Wextra -Werror
        -Wno-unused-parameter
        -Wno-missing-field-initializers)

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

if(NOT TARGET agdns_tls)
    add_subdirectory(${DNSLIBS_DIR}/tls ${CMAKE_BINARY_DIR}/agdns_tls)
endif(NOT TARGET agdns_tls)

if (NOT TARGET libevent)
    add_subdirectory(${THIRD_PARTY_DIR}/libevent ${CMAKE_BINARY_DIR}/third-party/libevent)
endif ()

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/third-party/ldns)
endif ()

if (NOT TARGET libcurl)
    add_subdirectory(${THIRD_PARTY_DIR}/curl ${CMAKE_BINARY_DIR}/third-party/curl)
endif ()

if(NOT TARGET ngtcp2)
    add_subdirectory(${THIRD_PARTY_DIR}/ngtcp2 ${CMAKE_BINARY_DIR}/third-party/ngtcp2)
endif(NOT TARGET ngtcp2)

target_include_directories(upstream PUBLIC include)
target_include_directories(upstream PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(upstream PRIVATE ../third-party/ngtcp2/ag_ngtcp2_crypto/includes)
target_link_libraries(upstream dnslibs_common dnsstamp dnscrypt agdns_tls ngtcp2 ag_ngtcp2_crypto_openssl)
target_link_libraries(upstream boringssl_static libevent ldns libcurl)

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(upstream)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_upstream ${TEST_DIR} "" TRUE FALSE)
add_unit_test(test_upstream_utils ${TEST_DIR} "" TRUE TRUE)
