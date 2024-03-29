cmake_minimum_required(VERSION 3.24)
project(dnsfilter)

set(CMAKE_CXX_STANDARD 20)

set(DNSLIBS_DIR ..)
set(SRC_DIR src)
set(TEST_DIR test)

set(SRCS
        engine.cpp
        filter.cpp
        rule_utils.cpp
        dnsrewrite.cpp
        denyallow.cpp
        filtering_log_action.cpp
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

if(NOT TARGET dnsproxy)
    add_subdirectory(${DNSLIBS_DIR}/proxy ${CMAKE_BINARY_DIR}/proxy)
endif(NOT TARGET dnsproxy)

find_package(ldns REQUIRED)
find_package(klib REQUIRED)
find_package(magic_enum REQUIRED)
find_package(tldregistry REQUIRED)

set_target_properties(dnsfilter PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnsfilter PUBLIC ./include)
target_link_libraries(dnsfilter dnslibs_common dnsproxy ldns::ldns klib::klib magic_enum::magic_enum
        tldregistry::tldregistry)
if (NOT MSVC)
    target_compile_options(dnsfilter PRIVATE -Wall -Wextra -Wformat=2 -Wno-unused-parameter)
    target_compile_options(dnsfilter PRIVATE -fno-exceptions)
else()
    target_compile_options(dnsfilter PRIVATE /W3)
    target_compile_options(dnsfilter PRIVATE -EHs-c-)
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
add_unit_test(dnsrewrite_test ${TEST_DIR} ${SRC_DIR} TRUE TRUE)
add_unit_test(filtering_log_action_test ${TEST_DIR} ${SRC_DIR} TRUE TRUE)
