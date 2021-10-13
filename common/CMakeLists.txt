cmake_minimum_required(VERSION 3.1)
project(dnslibs_common)
include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.py" SCOPE_NAME agdns)

set(CMAKE_CXX_STANDARD 17)

set(SRC_DIR src)

set(SRCS
        ${SRC_DIR}/utils.cpp
        ${SRC_DIR}/sys.cpp
        ${SRC_DIR}/file.cpp
        ${SRC_DIR}/logger.cpp
        ${SRC_DIR}/socket_address.cpp
        ${SRC_DIR}/net_utils.cpp
        ${SRC_DIR}/clock.cpp
        ${SRC_DIR}/cesu8.cpp
        ${SRC_DIR}/route_resolver.cpp
        ${SRC_DIR}/event_loop.cpp
        ${SRC_DIR}/base64.cpp
        ${SRC_DIR}/deferred_arg.cpp
    )

add_library(dnslibs_common STATIC EXCLUDE_FROM_ALL ${SRCS})

# workaround for successful build with spdlog headers
if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -Werror)
else ()
    target_compile_options(dnslibs_common PUBLIC -Wno-c++98-compat -Wno-c++98-compat-pedantic
        -Wno-documentation-unknown-command -Wno-newline-eof -Wno-return-std-move-in-c++11)
    target_compile_definitions(dnslibs_common PUBLIC
            FMT_EXCEPTIONS=0
            WIN32_LEAN_AND_MEAN
            NOMINMAX)
endif ()

set_target_properties(dnslibs_common PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnslibs_common PUBLIC include)
target_compile_definitions(dnslibs_common PUBLIC PCRE2_STATIC=1 PCRE2_CODE_UNIT_WIDTH=8 SPDLOG_NO_EXCEPTIONS=1)
target_link_libraries(dnslibs_common CONAN_PKG::spdlog CONAN_PKG::libevent CONAN_PKG::pcre2)
target_link_libraries(dnslibs_common CONAN_PKG::magic_enum)

target_compile_options(dnslibs_common PRIVATE -Wall -Wextra)
target_compile_options(dnslibs_common PUBLIC -Wno-format-nonliteral) # for fmt's chrono build
if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -fno-exceptions)
endif()

if (MSVC)
    target_link_libraries(dnslibs_common ws2_32.lib Iphlpapi.lib)
else ()
    target_compile_options(dnslibs_common PUBLIC -pthread)
endif ()

enable_testing()
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/add_unit_test.cmake)
link_libraries(dnslibs_common)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(cache_test ${TEST_DIR} "" TRUE TRUE)
add_unit_test(utils_test ${TEST_DIR} "" TRUE TRUE)
