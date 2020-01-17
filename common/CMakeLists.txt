cmake_minimum_required(VERSION 3.1)
project(dnslibs_common)

set(CMAKE_CXX_STANDARD 17)

set(SRC_DIR src)
set(THIRD_PARTY_DIR ../third-party)

set(SRCS
        ${SRC_DIR}/utils.cpp
        ${SRC_DIR}/sys.cpp
        ${SRC_DIR}/file.cpp
        ${SRC_DIR}/logger.cpp
        ${SRC_DIR}/socket_address.cpp
        ${SRC_DIR}/net_utils.cpp
        ${SRC_DIR}/clock.cpp
    )

add_library(dnslibs_common STATIC EXCLUDE_FROM_ALL ${SRCS})

# workaround for successful build with spdlog headers
if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -Werror)
else ()
    target_compile_options(dnslibs_common PUBLIC -Wno-c++98-compat -Wno-c++98-compat-pedantic
        -Wno-documentation-unknown-command -Wno-newline-eof -Wno-return-std-move-in-c++11)
    add_definitions(-DFMT_EXCEPTIONS=0)
endif ()

if(NOT TARGET spdlog)
    set(SPDLOG_NO_EXCEPTIONS ON CACHE BOOL "" FORCE)
    add_subdirectory(${THIRD_PARTY_DIR}/spdlog ${CMAKE_BINARY_DIR}/third-party/spdlog)
endif(NOT TARGET spdlog)

if (NOT TARGET libevent)
    add_subdirectory(${THIRD_PARTY_DIR}/libevent ${CMAKE_BINARY_DIR}/libevent)
endif ()

if (NOT TARGET ldns)
    add_subdirectory(${THIRD_PARTY_DIR}/ldns ${CMAKE_BINARY_DIR}/ldns)
endif ()

set_target_properties(dnslibs_common PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnslibs_common PUBLIC ./include ../third-party/magic_enum)
target_link_libraries(dnslibs_common spdlog libevent ldns)

target_compile_options(dnslibs_common PRIVATE -Wall -Wextra)
target_compile_options(dnslibs_common PUBLIC -Wno-format-nonliteral) # for fmt's chrono build
if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -fno-exceptions)
endif()

enable_testing()
if (NOT TARGET tests)
    add_subdirectory(${THIRD_PARTY_DIR}/googletest ${CMAKE_BINARY_DIR}/googletest)
    add_custom_target(tests)
endif ()

link_libraries(gtest gtest_main dnslibs_common)

add_executable(cache_test EXCLUDE_FROM_ALL test/cache_test.cpp)
add_test(cache_test cache_test)
add_dependencies(tests cache_test)
