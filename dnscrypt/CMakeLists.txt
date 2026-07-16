cmake_minimum_required(VERSION 3.24)
project(agdns_dnscrypt C CXX)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if (NOT TARGET dnsstamp)
    add_subdirectory(${DNSLIBS_DIR}/dnsstamp ${CMAKE_BINARY_DIR}/dnsstamp)
endif ()

if(NOT TARGET dnslibs_net)
    add_subdirectory(${DNSLIBS_DIR}/net ${CMAKE_BINARY_DIR}/net)
endif(NOT TARGET dnslibs_net)

add_library(dnscrypt EXCLUDE_FROM_ALL
        include/dns/dnscrypt/dns_crypt_cipher.h
        include/dns/dnscrypt/dns_crypt_client.h
        include/dns/dnscrypt/dns_crypt_consts.h
        include/dns/dnscrypt/dns_crypt_server_info.h
        include/dns/dnscrypt/dns_crypt_utils.h
        include/dns/dnscrypt/dns_crypt_ldns.h
        dns_crypt_cipher.cpp
        dns_crypt_client.cpp
        dns_crypt_ldns.cpp
        dns_crypt_padding.cpp
        dns_crypt_padding.h
        dns_crypt_server_info.cpp
        dns_crypt_utils.cpp
        )

find_package(libsodium REQUIRED)
find_package(ldns REQUIRED)

set_target_properties(dnscrypt PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnscrypt PUBLIC include)
target_link_libraries(dnscrypt dnsstamp dnslibs_net ldns::ldns libsodium::libsodium)

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnscrypt)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

# Resolved relative to this module so the include is correct regardless of which
# CMakeLists.txt is the top-level project (e.g. on Windows the build is driven
# from platform/windows/capi, so CMAKE_SOURCE_DIR is not the repo root).
set(AG_TEST_HELPERS ${DNSLIBS_DIR}/common/test_helpers)

add_unit_test(dns_crypt_test "${TEST_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src;${AG_TEST_HELPERS}" TRUE FALSE)

# The LoopbackDnscryptServer (header-only DNSCrypt responder on 127.0.0.1)
# lives in common/test_helpers but requires the real dnscrypt::Client + libsodium
# to exercise. Built here because the dnscrypt lib already links them. Registered
# with EXPAND_GTEST=FALSE (like dns_crypt_test) so `ctest -R
# loopback_dnscrypt_server_test` selects the whole suite.
add_unit_test(loopback_dnscrypt_server_test "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE FALSE)
