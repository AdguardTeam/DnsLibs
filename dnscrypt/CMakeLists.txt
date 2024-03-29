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

add_unit_test(dns_crypt_test "${TEST_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src" TRUE FALSE)
