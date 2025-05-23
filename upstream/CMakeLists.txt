cmake_minimum_required(VERSION 3.24)
project(agdns_upstream C CXX)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

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
if (APPLE)
    target_sources(upstream PRIVATE
            upstream_system.h upstream_system.cpp
            system_resolver.h system_resolver.cpp
    )
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

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(upstream)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_upstream "${TEST_DIR}" "${DNSLIBS_DIR}/dnscrypt/src" TRUE FALSE)
add_unit_test(test_upstream_utils "${TEST_DIR}" "" TRUE TRUE)
if (APPLE)
    add_unit_test(test_system_resolver "${TEST_DIR}" "" TRUE TRUE)
endif ()
add_unit_test(test_dot_invalid_address "${TEST_DIR}" "${DNSLIBS_DIR}/upstream/src" TRUE TRUE)
add_unit_test(test_bootstrapper "${TEST_DIR}" "${DNSLIBS_DIR}/upstream/src" TRUE TRUE)
add_unit_test(test_doh_credentials "${TEST_DIR}" "${DNSLIBS_DIR}/upstream/src" TRUE TRUE)
