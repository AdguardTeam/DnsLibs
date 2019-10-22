cmake_minimum_required(VERSION 3.1)
project(dnsfilter)

set(CMAKE_CXX_STANDARD 17)

set(DNSLIBS_DIR ..)
set(SRC_DIR src)
set(TEST_DIR test)
set(THIRD_PARTY_DIR ${DNSLIBS_DIR}/third-party)

set(SRCS
        ${SRC_DIR}/engine.cpp
        ${SRC_DIR}/filter.cpp
        ${SRC_DIR}/rule_utils.cpp
    )

add_library(dnsfilter STATIC EXCLUDE_FROM_ALL ${SRCS})

# workaround for successful build with spdlog headers
if (NOT MSVC)
    target_compile_options(dnsfilter PRIVATE -Werror)
else ()
    add_definitions(-DFMT_EXCEPTIONS=0)
endif ()

if(NOT TARGET pcre2)
    set(PCRE2_BUILD_PCRE2GREP OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory(${THIRD_PARTY_DIR}/pcre2 ${CMAKE_BINARY_DIR}/third-party/pcre2)
endif(NOT TARGET pcre2)

if(NOT TARGET spdlog)
    set(SPDLOG_NO_EXCEPTIONS ON CACHE BOOL "" FORCE)
    add_subdirectory(${THIRD_PARTY_DIR}/spdlog ${CMAKE_BINARY_DIR}/third-party/spdlog)
endif(NOT TARGET spdlog)

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

set_target_properties(dnsfilter PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsfilter PUBLIC ./include)
target_include_directories(dnsfilter PRIVATE ${THIRD_PARTY_DIR}/klib)
target_include_directories(dnsfilter PRIVATE ${CMAKE_BINARY_DIR}/third-party/pcre2)
target_compile_definitions(dnsfilter PUBLIC PCRE2_STATIC=1 PCRE2_CODE_UNIT_WIDTH=8)
target_link_libraries(dnsfilter dnslibs_common spdlog pcre2-8)

target_compile_options(dnsfilter PRIVATE -Wall -Wextra -Wformat=2 -Wno-unused-parameter)
if (NOT MSVC)
    target_compile_options(dnsfilter PRIVATE -fno-exceptions)
endif()


enable_testing()

include_directories(./src)

add_custom_target(dnsfilter_run_benchmark)
add_executable(dnsfilter_benchmark EXCLUDE_FROM_ALL test/benchmark.cpp)
target_link_libraries(dnsfilter_benchmark dnsfilter)
add_dependencies(dnsfilter_run_benchmark dnsfilter_benchmark)
add_custom_command(TARGET dnsfilter_run_benchmark COMMAND ${CMAKE_COMMAND} -E copy
                   ../test/dnsfilter_benchmark_runner.py
                   ${CMAKE_CURRENT_BINARY_DIR}/dnsfilter_benchmark_runner.py)
add_custom_command(TARGET dnsfilter_run_benchmark COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dnsfilter_benchmark_runner.py)


if (NOT TARGET tests)
    add_subdirectory(${THIRD_PARTY_DIR}/googletest googletest)
    add_custom_target(tests)
endif ()

link_libraries(gtest gtest_main dnsfilter)

add_executable(dnsfilter_test EXCLUDE_FROM_ALL ${TEST_DIR}/dnsfilter_test.cpp)
add_test(dnsfilter_test dnsfilter_test)

add_dependencies(tests dnsfilter_test)
