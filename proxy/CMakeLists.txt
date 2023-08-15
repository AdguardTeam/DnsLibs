cmake_minimum_required(VERSION 3.1)
project(dnsproxy)
include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.py" SCOPE_NAME agdns)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ..)
set(TEST_DIR test)

if(SANITIZE)
    add_compile_options("-fsanitize=address")
    link_libraries("-fsanitize=address")
endif(SANITIZE)

set(SRCS
        dnsproxy.cpp
        dns64.cpp
        dns_forwarder.cpp
        dns_forwarder_utils.cpp
        dnsproxy_listener.cpp
        retransmission_detector.cpp
        dns_truncate.cpp
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

if(NOT TARGET dnslibs_net)
    add_subdirectory(${DNSLIBS_DIR}/net ${CMAKE_BINARY_DIR}/net)
endif(NOT TARGET dnslibs_net)

set_target_properties(dnsproxy PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsproxy PUBLIC ./include)
target_link_libraries(dnsproxy dnslibs_common dnsfilter upstream dnslibs_net CONAN_PKG::ldns CONAN_PKG::libuv)

if (NOT MSVC)
    target_compile_options(dnsproxy PRIVATE -Wall -Wextra -Wformat=2 -Wno-unused-parameter -Wno-unused-variable -Wno-ignored-qualifiers -Wno-missing-field-initializers)
    target_compile_options(dnsproxy PRIVATE -fno-exceptions)
else()
    target_compile_options(dnsproxy PRIVATE /W3)
    target_compile_options(dnsproxy PRIVATE /EHs-c-)
endif()


enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnsproxy)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

configure_file(test/cname_blocking_test_filter.txt cname_blocking_test_filter.txt COPYONLY)
configure_file(test/blocking_modes_test_filter.txt blocking_modes_test_filter.txt COPYONLY)
configure_file(test/whitelist_test_filter.txt whitelist_test_filter.txt COPYONLY)
configure_file(test/bad_test_filter.txt bad_test_filter.txt COPYONLY)
configure_file(test/crash_regress_test_filter.txt crash_regress_test_filter.txt COPYONLY)

add_unit_test(dns64_test ${TEST_DIR} "" TRUE TRUE)
add_unit_test(dnsproxy_test ${TEST_DIR} "" TRUE TRUE)
add_unit_test(listener_test ${TEST_DIR} "" TRUE FALSE)
add_unit_test(truncate_test ${TEST_DIR} "" TRUE TRUE)

add_executable(listener_standalone EXCLUDE_FROM_ALL test/listener_standalone.cpp)
add_executable(cache_benchmark EXCLUDE_FROM_ALL test/cache_benchmark.cpp)
add_dependencies(tests listener_standalone)
if (NOT MSVC)
    target_link_libraries(listener_standalone resolv)
endif()
