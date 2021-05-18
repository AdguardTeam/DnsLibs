cmake_minimum_required(VERSION 3.1)
project(dnslibs_net)

set(CMAKE_CXX_STANDARD 17)

set(DNSLIBS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(THIRD_PARTY_DIR "${DNSLIBS_DIR}/third-party")

set(SRCS
        ${SRC_DIR}/certificate_verifier.cpp
        ${SRC_DIR}/application_verifier.cpp
        ${SRC_DIR}/default_verifier.cpp
        ${SRC_DIR}/tls_session_cache.cpp
        ${SRC_DIR}/socket.cpp
        ${SRC_DIR}/socket_factory.cpp
        ${SRC_DIR}/blocking_socket.cpp
        ${SRC_DIR}/tcp_stream.cpp
        ${SRC_DIR}/udp_socket.cpp
        ${SRC_DIR}/tcp_dns_buffer.cpp
        ${SRC_DIR}/proxied_socket.cpp
        ${SRC_DIR}/outbound_proxy.cpp
        ${SRC_DIR}/outbound_http_proxy.cpp
        ${SRC_DIR}/outbound_socks_proxy.cpp
        )

add_library(dnslibs_net STATIC EXCLUDE_FROM_ALL ${SRCS})
set_target_properties(dnslibs_net PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(dnslibs_net PRIVATE
        -Wall -Wextra -Werror
        -Wno-unused-parameter
        -Wno-missing-field-initializers)


if (NOT TARGET libevent)
    add_subdirectory(${THIRD_PARTY_DIR}/libevent ${CMAKE_BINARY_DIR}/libevent)
endif ()

if (NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif ()

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

target_include_directories(dnslibs_net PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(dnslibs_net PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dnslibs_net dnslibs_common libevent boringssl_static)

if (APPLE)
    target_link_libraries(dnslibs_net "-framework CoreFoundation" "-framework Security")
endif ()

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnslibs_net)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_tcp_stream ${TEST_DIR} "src" TRUE TRUE)
