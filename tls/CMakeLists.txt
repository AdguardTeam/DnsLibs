cmake_minimum_required(VERSION 3.6)
project(agdns_tls C CXX)

set(CMAKE_CXX_STANDARD 17)

set(DNSLIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_DIR ${DNSLIBS_DIR}/third-party)
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(agdns_tls EXCLUDE_FROM_ALL
        ${SRC_DIR}/certificate_verifier.cpp
        ${SRC_DIR}/application_verifier.cpp
        ${SRC_DIR}/default_verifier.cpp
    )

set_target_properties(agdns_tls PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(NOT TARGET dnslibs_common)
    add_subdirectory(${DNSLIBS_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET dnslibs_common)

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

target_include_directories(agdns_tls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(agdns_tls PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(agdns_tls dnslibs_common boringssl_static)
if (APPLE)
    target_link_libraries(agdns_tls "-framework CoreFoundation" "-framework Security")
endif ()
