cmake_minimum_required(VERSION 3.24)
project(dnslibs_common)

set(CMAKE_CXX_STANDARD 20)

find_package(libevent REQUIRED)
find_package(pcre2 REQUIRED)
find_package(magic_enum REQUIRED)
find_package(native_libs_common REQUIRED)
find_package(libuv REQUIRED)

set(SRCS
        sys.cpp
        event_loop.cpp
)

add_library(dnslibs_common STATIC EXCLUDE_FROM_ALL ${SRCS})

# workaround for successful build with spdlog headers
if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -Werror)
else ()
    target_compile_options(dnslibs_common PRIVATE /W3)
    target_compile_definitions(dnslibs_common PUBLIC
            FMT_EXCEPTIONS=0
            WIN32_LEAN_AND_MEAN
            NOMINMAX)
    target_compile_options(dnslibs_common PUBLIC -U__cpp_char8_t)
endif ()

set_target_properties(dnslibs_common PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnslibs_common PUBLIC include)
target_compile_definitions(dnslibs_common PUBLIC PCRE2_STATIC=1 PCRE2_CODE_UNIT_WIDTH=8 SPDLOG_NO_EXCEPTIONS=1)
target_link_libraries(dnslibs_common libevent::libevent pcre2::pcre2)
target_link_libraries(dnslibs_common magic_enum::magic_enum native_libs_common::native_libs_common libuv::libuv)

if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -Wall -Wextra)
    target_compile_options(dnslibs_common PUBLIC -Wno-format-nonliteral) # for fmt's chrono build
    target_compile_options(dnslibs_common PUBLIC -Wno-unknown-warning-option -Wno-deprecated-experimental-coroutine)
    target_compile_options(dnslibs_common PRIVATE -fno-exceptions)
else()
    target_compile_options(dnslibs_common PRIVATE /W3)
    target_compile_options(dnslibs_common PRIVATE /EHs-c-)
endif()

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnslibs_common)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_event_loop ${TEST_DIR} . TRUE TRUE)
