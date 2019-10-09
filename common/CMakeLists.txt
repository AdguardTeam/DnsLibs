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

set_target_properties(dnslibs_common PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dnslibs_common PUBLIC ./include)
target_link_libraries(dnslibs_common spdlog)

target_compile_options(dnslibs_common PRIVATE -Wall -Wextra)
if (NOT MSVC)
    target_compile_options(dnslibs_common PRIVATE -fno-exceptions)
endif()
