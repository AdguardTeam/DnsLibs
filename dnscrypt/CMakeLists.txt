cmake_minimum_required(VERSION 3.6)
project(agdns_dnscrypt C CXX)

set(CMAKE_CXX_STANDARD 17)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third-party)
set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if (NOT TARGET dnsstamp)
    add_subdirectory(${DNSLIBS_DIR}/dnsstamp ${CMAKE_BINARY_DIR}/dnsstamp)
endif ()

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/ldns)
endif ()

if (NOT TARGET sodium)
    add_subdirectory(${THIRD_PARTY_DIR}/sodium ${CMAKE_BINARY_DIR}/sodium)
endif ()

add_library(dnscrypt EXCLUDE_FROM_ALL
        include/dns_crypt_cipher.h
        include/dns_crypt_client.h
        include/dns_crypt_consts.h
        include/dns_crypt_ldns.h
        include/dns_crypt_server_info.h
        include/dns_crypt_utils.h
        src/dns_crypt_cipher.cpp
        src/dns_crypt_client.cpp
        src/dns_crypt_ldns.cpp
        src/dns_crypt_padding.cpp
        src/dns_crypt_padding.h
        src/dns_crypt_server_info.cpp
        src/dns_crypt_utils.cpp)

set_target_properties(dnscrypt PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnscrypt PUBLIC include)
target_include_directories(dnscrypt PUBLIC ${THIRD_PARTY_DIR}/sodium/libsodium/src/libsodium/include)
target_include_directories(dnscrypt PUBLIC ${THIRD_PARTY_DIR}/sodium/libsodium/src/libsodium/include/sodium)
target_include_directories(dnscrypt PUBLIC ${CMAKE_BINARY_DIR}) # sodium/version.h
target_link_libraries(dnscrypt dnsstamp ldns sodium)

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnscrypt)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(dns_crypt_test ${TEST_DIR} "" TRUE FALSE)
