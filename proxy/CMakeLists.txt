cmake_minimum_required(VERSION 3.1)
project(dnsproxy)

set(CMAKE_CXX_STANDARD 17)

set(DNSLIBS_DIR ..)
set(SRC_DIR src)
set(TEST_DIR test)
set(THIRD_PARTY_DIR ${DNSLIBS_DIR}/third-party)

set(SRCS
        ${SRC_DIR}/dnsproxy.cpp
        ${SRC_DIR}/dns64.cpp
        ${SRC_DIR}/dns_forwarder.cpp
        ${SRC_DIR}/dnsproxy_listener.cpp
    )

add_library(dnsproxy EXCLUDE_FROM_ALL ${SRCS})

# workaround for successful build with spdlog headers
if (NOT MSVC)
    target_compile_options(dnsproxy PRIVATE -Werror)
else ()
    add_definitions(-DFMT_EXCEPTIONS=0)
endif ()

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

if(NOT TARGET dnsfilter)
    add_subdirectory(${DNSLIBS_DIR}/dnsfilter ${CMAKE_BINARY_DIR}/dnsfilter)
endif(NOT TARGET dnsfilter)

if(NOT TARGET upstream)
    add_subdirectory(${DNSLIBS_DIR}/upstream ${CMAKE_BINARY_DIR}/upstream)
endif(NOT TARGET upstream)

if(NOT TARGET agdns_tls)
    add_subdirectory(${DNSLIBS_DIR}/tls ${CMAKE_BINARY_DIR}/agdns_tls)
endif(NOT TARGET agdns_tls)

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/ldns)
endif ()

if(NOT TARGET uv)
    add_subdirectory(${THIRD_PARTY_DIR}/libuv ${CMAKE_BINARY_DIR}/third-party/libuv)
endif(NOT TARGET uv)

set_target_properties(dnsproxy PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsproxy PUBLIC ./include)
target_include_directories(dnsproxy PRIVATE ./src)
target_link_libraries(dnsproxy dnslibs_common dnsfilter upstream agdns_tls ldns uv_a)

target_compile_options(dnsproxy PRIVATE -Wall -Wextra -Wformat=2 -Wno-unused-parameter -Wno-unused-variable -Wno-ignored-qualifiers -Wno-missing-field-initializers)
if (NOT MSVC)
    target_compile_options(dnsproxy PRIVATE -fno-exceptions)
endif()


enable_testing()
if (NOT TARGET tests)
    add_subdirectory(${THIRD_PARTY_DIR}/googletest ${CMAKE_BINARY_DIR}/googletest)
    add_custom_target(tests)
endif ()

link_libraries(gtest gtest_main dnsproxy)
include_directories(./src)

add_executable(dns64_test EXCLUDE_FROM_ALL test/dns64_test.cpp)
add_test(dns64_test dns64_test)
add_dependencies(tests dns64_test)

add_executable(dnsproxy_test EXCLUDE_FROM_ALL test/dnsproxy_test.cpp)
add_test(dnsproxy_test dnsproxy_test)
add_dependencies(tests dnsproxy_test)
configure_file(test/cname_blocking_test_filter.txt cname_blocking_test_filter.txt COPYONLY)
configure_file(test/blocking_modes_test_filter.txt blocking_modes_test_filter.txt COPYONLY)
configure_file(test/whitelist_test_filter.txt whitelist_test_filter.txt COPYONLY)
configure_file(test/bad_test_filter.txt bad_test_filter.txt COPYONLY)
configure_file(test/crash_regress_test_filter.txt crash_regress_test_filter.txt COPYONLY)

add_executable(listener_test EXCLUDE_FROM_ALL test/listener_test.cpp)
add_test(listener_test listener_test)
add_dependencies(tests listener_test)

add_executable(listener_standalone EXCLUDE_FROM_ALL test/listener_standalone.cpp)
add_executable(cache_benchmark EXCLUDE_FROM_ALL test/cache_benchmark.cpp)
