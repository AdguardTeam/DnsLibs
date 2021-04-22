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

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/ldns)
endif ()

set_target_properties(dnsfilter PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsfilter PUBLIC ./include)
target_include_directories(dnsfilter PRIVATE ${THIRD_PARTY_DIR}/klib)
target_link_libraries(dnsfilter dnslibs_common ldns)
target_compile_options(dnsfilter PRIVATE -Wall -Wextra -Wformat=2 -Wno-unused-parameter)
if (NOT MSVC)
    target_compile_options(dnsfilter PRIVATE -fno-exceptions)
endif()


enable_testing()

add_executable(dnsfilter_benchmark EXCLUDE_FROM_ALL test/benchmark.cpp)
target_link_libraries(dnsfilter_benchmark dnsfilter)
add_dependencies(tests dnsfilter_benchmark)

add_custom_target(dnsfilter_run_benchmark)
add_dependencies(dnsfilter_run_benchmark dnsfilter_benchmark)
add_custom_command(TARGET dnsfilter_run_benchmark COMMAND ${CMAKE_COMMAND} -E copy
                   ../test/dnsfilter_benchmark_runner.py
                   ${CMAKE_CURRENT_BINARY_DIR}/dnsfilter_benchmark_runner.py)
add_custom_command(TARGET dnsfilter_run_benchmark COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dnsfilter_benchmark_runner.py)


include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnsfilter)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(dnsfilter_test ${TEST_DIR} ${SRC_DIR} TRUE TRUE)
