cmake_minimum_required(VERSION 3.24)
project(adig CXX)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# Ensure the upstream library (and all of its transitive dependencies) is
# available. The top-level CMakeLists.txt adds `proxy` first, which in turn
# adds `upstream`, so this guard normally does nothing.
if(NOT TARGET upstream)
    add_subdirectory(${DNSLIBS_DIR}/upstream ${CMAKE_BINARY_DIR}/upstream)
endif()

# Unit-test machinery. Includes cmake/add_unit_test.cmake, which also creates
# the `tests` custom target when it does not yet exist. enable_testing() is
# called locally because the top-level CMakeLists.txt calls it after this
# subdirectory is added (mirrors common/CMakeLists.txt).
enable_testing()
include(${DNSLIBS_DIR}/cmake/add_unit_test.cmake)

# Pure, event-loop-free CLI logic shared by the `adig` executable and its unit
# tests. Linked PUBLIC to `upstream` so that the object files (which reference
# ldns/fmt symbols) and the transitive include directories/dependencies
# propagate to both the executable and the test target. An OBJECT library is
# used so the pure code is compiled exactly once and linked into both.
#
# Split by concern: argument parsing (adig_cli.cpp), the EDNS/IP helpers
# (adig_cli_edns.cpp) and the packet/formatting logic (adig_cli_packet.cpp).
# The few internal helpers shared across the translation units live in
# adig_cli_internal.h (included only by these sources, not part of the public
# adig_cli.h interface).
add_library(adig_cli OBJECT
        adig_cli.cpp
        adig_cli_edns.cpp
        adig_cli_packet.cpp)
target_include_directories(adig_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(adig_cli PUBLIC upstream)

# dig-like DNS query tool supporting plain DNS, DoT, DoH, DoQ and DNSCrypt.
# Links the `adig_cli` pure layer; `upstream` (and its transitive dependencies:
# ldns, fmt, libevent, ngtcp2, ada, dnslibs_common, dnslibs_net, etc.) arrives
# via the PUBLIC link on adig_cli.
add_executable(adig EXCLUDE_FROM_ALL adig.cpp)
target_link_libraries(adig PRIVATE adig_cli)
add_dependencies(tests adig)

# Unit tests for the pure CLI layer (adig_cli). `link_libraries(adig_cli)`
# applies to subsequently-defined targets in this directory (the test
# executable created by add_unit_test), so it inherits adig_cli and, via its
# PUBLIC link, upstream. gtest is added by add_unit_test itself. gtest's
# default main() is bundled in the gtest::gtest target, so the test sources
# carry only TEST() cases (no explicit main()).
#
# The tests mirror the source split: shared helpers live in the inline
# test_adig_cli_helpers.h header; parser tests in test_adig_cli.cpp, EDNS/IP
# tests in test_adig_cli_edns.cpp and packet/format tests in
# test_adig_cli_packet.cpp. add_unit_test compiles a single primary source
# (test_adig_cli.cpp), so the remaining sources are appended to the target.
link_libraries(adig_cli)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
add_unit_test(test_adig_cli ${TEST_DIR} "" TRUE TRUE)
target_sources(test_adig_cli PRIVATE
        ${TEST_DIR}/test_adig_cli_edns.cpp
        ${TEST_DIR}/test_adig_cli_packet.cpp)
target_include_directories(test_adig_cli PRIVATE ${TEST_DIR})
