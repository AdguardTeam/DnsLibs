cmake_minimum_required(VERSION 3.24)
project(agdns_upstream C CXX)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

option(USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM "Enable interface name resolution in SystemUpstream on Android (requires JNI)" OFF)

add_library(upstream EXCLUDE_FROM_ALL
        upstream.cpp
        upstream_doh.h upstream_doh.cpp
        upstream_dot.h upstream_dot.cpp
        upstream_doq.h upstream_doq.cpp
        upstream_plain.h upstream_plain.cpp
        connection.h connection.cpp
        dns_framed.h dns_framed.cpp
        bootstrapper.cpp
        upstream_dnscrypt.h upstream_dnscrypt.cpp
        resolver.h resolver.cpp
        upstream_utils.cpp
)
# Platform-specific system resolver implementations
if (APPLE OR ANDROID)
    target_sources(upstream PRIVATE
            upstream_system.h upstream_system.cpp
            system_resolver.h
    )
    if (APPLE)
        target_sources(upstream PRIVATE system_resolver_apple.cpp)
    elseif (ANDROID)
        target_sources(upstream PRIVATE 
            system_resolver_android.cpp
            android_res_api.h android_res_api.cpp
        )
        if (USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM)
            target_sources(upstream PRIVATE
                ${DNSLIBS_DIR}/platform/android/dnsproxy/lib/src/main/cpp/android_context_manager.cpp
            )
            target_include_directories(upstream PRIVATE
                ${DNSLIBS_DIR}/platform/android/dnsproxy/lib/src/main/cpp
            )
            target_compile_definitions(upstream PRIVATE USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM)
        endif()
    endif()
endif ()

set_target_properties(upstream PROPERTIES POSITION_INDEPENDENT_CODE ON)
if (NOT MSVC)
    target_compile_options(upstream PRIVATE
            -Wall -Wextra -Werror
            -Wno-unused-parameter
            -Wno-missing-field-initializers
    )
else ()
    target_compile_options(upstream PRIVATE /W3)
endif ()

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wgnu-designator" COMPILER_SUPPORTS_GNU_DESIGNATOR)
if (COMPILER_SUPPORTS_GNU_DESIGNATOR)
    target_compile_options(upstream PRIVATE -Wno-gnu-designator)
endif ()
check_cxx_compiler_flag("-Wc99-designator" COMPILER_SUPPORTS_C99_DESIGNATOR)
if (COMPILER_SUPPORTS_C99_DESIGNATOR)
    target_compile_options(upstream PRIVATE -Wno-c99-designator)
endif ()

if (NOT TARGET agdns_dnsstamp)
    add_subdirectory(${DNSLIBS_DIR}/dnsstamp ${CMAKE_BINARY_DIR}/dnsstamp)
endif ()

if (NOT TARGET agdns_dnscrypt)
    add_subdirectory(${DNSLIBS_DIR}/dnscrypt ${CMAKE_BINARY_DIR}/dnscrypt)
endif ()

if (NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif (NOT TARGET dnslibs_common)

if (NOT TARGET dnslibs_net)
    add_subdirectory(${DNSLIBS_DIR}/net ${CMAKE_BINARY_DIR}/net)
endif (NOT TARGET dnslibs_net)

find_package(libevent REQUIRED)
find_package(ldns REQUIRED)
find_package(magic_enum REQUIRED)
find_package(ngtcp2 REQUIRED)
find_package(ada REQUIRED)

target_include_directories(upstream PUBLIC include)
target_include_directories(upstream PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(upstream dnslibs_common dnsstamp dnscrypt dnslibs_net)
target_link_libraries(upstream magic_enum::magic_enum libevent::libevent ldns::ldns)
target_link_libraries(upstream ngtcp2::ngtcp2 ada::ada)

# Android-specific libraries
if (ANDROID)
    target_link_libraries(upstream log)
endif ()

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(upstream)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

set(AG_TEST_HELPERS ${DNSLIBS_DIR}/common/test_helpers)

if (ANDROID)
    add_unit_test(test_upstream "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src;${DNSLIBS_DIR}/platform/android/dnsproxy/lib/src/main/cpp;${AG_TEST_HELPERS}" TRUE TRUE)
else()
    add_unit_test(test_upstream "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src;${AG_TEST_HELPERS}" TRUE TRUE)
endif()
# Validation cases (TEST_P): wrong options + invalid fingerprints. EXPAND_GTEST=FALSE.
if (ANDROID)
    add_unit_test(test_upstream_validation "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src;${DNSLIBS_DIR}/platform/android/dnsproxy/lib/src/main/cpp;${AG_TEST_HELPERS}" TRUE FALSE)
else()
    add_unit_test(test_upstream_validation "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src;${AG_TEST_HELPERS}" TRUE FALSE)
endif()
# Integration cases (TEST_P): real-network exchanges + dead-proxy failures. EXPAND_GTEST=FALSE.
if (ANDROID)
    add_unit_test(test_upstream_integration "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src;${DNSLIBS_DIR}/platform/android/dnsproxy/lib/src/main/cpp;${AG_TEST_HELPERS}" TRUE FALSE)
else()
    add_unit_test(test_upstream_integration "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src;${AG_TEST_HELPERS}" TRUE FALSE)
endif()
add_unit_test(test_upstream_utils "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE TRUE)
if (APPLE)
    add_unit_test(test_system_resolver "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE TRUE)
endif ()
add_unit_test(test_dot_invalid_address "${TEST_DIR}" "${DNSLIBS_DIR}/upstream/src;${AG_TEST_HELPERS}" TRUE TRUE)
add_unit_test(test_bootstrapper "${TEST_DIR}" "${DNSLIBS_DIR}/upstream/src;${AG_TEST_HELPERS}" TRUE TRUE)
add_unit_test(test_doh_credentials "${TEST_DIR}" "${DNSLIBS_DIR}/upstream/src;${AG_TEST_HELPERS}" TRUE FALSE) # TEST_P (DohUpstreamParamTest): FALSE per cmake/add_unit_test.cmake
# Shared test infrastructure (loopback DNS server, MockUpstream, integration
# guard) lives in common/test_helpers (header-only); the test itself is built
# here because MockUpstream derives from dns::Upstream and the round-trip tests
# exercise PlainUpstream, both of which require linking the upstream library.
add_unit_test(test_helpers_test "${TEST_DIR}" "${DNSLIBS_DIR}/common/test_helpers" TRUE TRUE)

# The test-certificate kit (PEM literals, OpenSSL loaders, TestCertificateVerifier)
# is header-only in common/test_helpers; the smoke test is built here because it
# links OpenSSL (transitively via upstream -> dnslibs_net) which common/ does not.
add_unit_test(test_certificates_test "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE TRUE)

# The LoopbackTlsServer (header-only DoT responder on 127.0.0.1) lives in
# common/test_helpers but requires OpenSSL + the real DotUpstream to exercise.
# Built here for the same reason as test_certificates_test: it links the
# upstream -> dnslibs_net -> OpenSSL chain that common/ cannot.
add_unit_test(loopback_tls_server_test "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE TRUE)

# The LoopbackDohServer (header-only DoH responder on 127.0.0.1, HTTP/1.1 +
# HTTP/2 over TLS) lives in common/test_helpers but requires the native_libs_common
# HTTP server headers + a real DohUpstream to exercise. Built here for the same
# reason as loopback_tls_server_test: it links the upstream ->
# dnslibs_net -> OpenSSL chain (which brings the http/* headers transitively).
add_unit_test(loopback_doh_server_test "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE TRUE)

# The LoopbackQuicServer (header-only DoQ responder on 127.0.0.1, raw QUIC +
# ngtcp2-crypto/BoringSSL server TLS, ALPN "doq", RFC 9250 2-byte stream
# framing) lives in common/test_helpers but requires ngtcp2 + libevent + a real
# DoqUpstream to exercise. Built here for the same reason as
# loopback_tls_server_test: it links the upstream -> ngtcp2 / dnslibs_net /
# libevent / OpenSSL chain that common/ cannot. ngtcp2::ngtcp2 is already linked
# to `upstream` (:95) and is transitively available to this test target.
add_unit_test(loopback_quic_server_test "${TEST_DIR}" "${AG_TEST_HELPERS}" TRUE TRUE)
