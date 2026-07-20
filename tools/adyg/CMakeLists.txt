cmake_minimum_required(VERSION 3.24)
project(adyg CXX)

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

# Pure, event-loop-free CLI logic shared by the `adyg` executable and its unit
# tests. Linked PUBLIC to `upstream` so that the object files (which reference
# ldns/fmt symbols) and the transitive include directories/dependencies
# propagate to both the executable and the test target. An OBJECT library is
# used so the pure code is compiled exactly once and linked into both.
#
# Split by concern: argument parsing (adyg_cli.cpp), the EDNS/IP helpers
# (adyg_cli_edns.cpp) and the packet/formatting logic (adyg_cli_packet.cpp).
# The few internal helpers shared across the translation units live in
# adyg_cli_internal.h (included only by these sources, not part of the public
# adyg_cli.h interface).
add_library(adyg_cli OBJECT
        adyg_cli.cpp
        adyg_cli_edns.cpp
        adyg_cli_packet.cpp)
target_include_directories(adyg_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(adyg_cli PUBLIC upstream)

# dig-like DNS query tool supporting plain DNS, DoT, DoH, DoQ and DNSCrypt.
# Links the `adyg_cli` pure layer; `upstream` (and its transitive dependencies:
# ldns, fmt, libevent, ngtcp2, ada, dnslibs_common, dnslibs_net, etc.) arrives
# via the PUBLIC link on adyg_cli.
add_executable(adyg EXCLUDE_FROM_ALL adyg.cpp)
target_link_libraries(adyg PRIVATE adyg_cli)
add_dependencies(tests adyg)

# Unit tests for the pure CLI layer (adyg_cli). `link_libraries(adyg_cli)`
# applies to subsequently-defined targets in this directory (the test
# executable created by add_unit_test), so it inherits adyg_cli and, via its
# PUBLIC link, upstream. gtest is added by add_unit_test itself. gtest's
# default main() is bundled in the gtest::gtest target, so the test sources
# carry only TEST() cases (no explicit main()).
#
# The tests mirror the source split: shared helpers live in the inline
# test_adyg_cli_helpers.h header; parser tests in test_adyg_cli.cpp, EDNS/IP
# tests in test_adyg_cli_edns.cpp and packet/format tests in
# test_adyg_cli_packet.cpp. add_unit_test compiles a single primary source
# (test_adyg_cli.cpp), so the remaining sources are appended to the target.
link_libraries(adyg_cli)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
add_unit_test(test_adyg_cli ${TEST_DIR} "" TRUE TRUE)
target_sources(test_adyg_cli PRIVATE
        ${TEST_DIR}/test_adyg_cli_edns.cpp
        ${TEST_DIR}/test_adyg_cli_packet.cpp)
target_include_directories(test_adyg_cli PRIVATE ${TEST_DIR})
