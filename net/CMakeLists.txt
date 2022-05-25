cmake_minimum_required(VERSION 3.1)
project(dnslibs_net)
include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.py" SCOPE_NAME agdns)

set(CMAKE_CXX_STANDARD 17)

set(DNSLIBS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

set(SRCS
        certificate_verifier.cpp
        application_verifier.cpp
        default_verifier.cpp
        tls_session_cache.cpp
        socket.cpp
        socket_factory.cpp
        blocking_socket.cpp
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
        )

add_library(dnslibs_net STATIC EXCLUDE_FROM_ALL ${SRCS})
set_target_properties(dnslibs_net PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(dnslibs_net PRIVATE
        -Wall -Wextra -Werror
        -Wno-unused-parameter
        -Wno-missing-field-initializers)

if (NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif ()

target_include_directories(dnslibs_net PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(dnslibs_net PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dnslibs_net dnslibs_common CONAN_PKG::libevent CONAN_PKG::openssl CONAN_PKG::magic_enum)

if (APPLE)
    target_link_libraries(dnslibs_net "-framework CoreFoundation" "-framework Security")
endif ()

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnslibs_net)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_tcp_stream ${TEST_DIR} "src" TRUE TRUE)
