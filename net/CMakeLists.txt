cmake_minimum_required(VERSION 3.24)
project(dnslibs_net)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

set(SRCS
        certificate_verifier.cpp
        application_verifier.cpp
        default_verifier.cpp
        tls_session_cache.cpp
        socket.cpp
        socket_factory.cpp
        tcp_stream.cpp
        udp_socket.cpp
        tcp_dns_buffer.cpp
        proxied_socket.cpp
        outbound_proxy.cpp
        outbound_http_proxy.cpp
        outbound_socks_proxy.cpp
        outbound_direct_proxy.cpp
        tls_codec.cpp
        secured_socket.cpp
        aio_socket.cpp
        utils.cpp
        )

add_library(dnslibs_net STATIC EXCLUDE_FROM_ALL ${SRCS})
set_target_properties(dnslibs_net PROPERTIES POSITION_INDEPENDENT_CODE ON)

if (NOT MSVC)
    target_compile_options(dnslibs_net PRIVATE
        -Wall -Wextra -Werror
        -Wno-unused-parameter
        -Wno-missing-field-initializers)
else()
    target_compile_options(dnslibs_net PRIVATE /W3)
endif()

if (NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif ()

find_package(libevent REQUIRED)
find_package(magic_enum REQUIRED)
find_package(OpenSSL REQUIRED)

target_include_directories(dnslibs_net PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(dnslibs_net PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dnslibs_net dnslibs_common libevent::libevent openssl::openssl magic_enum::magic_enum)

if (APPLE)
    target_link_libraries(dnslibs_net "-framework CoreFoundation" "-framework Security")
endif ()

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnslibs_net)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_tcp_stream ${TEST_DIR} . TRUE FALSE)
