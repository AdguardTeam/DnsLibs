cmake_minimum_required(VERSION 3.6)
project(ngtcp2)

if (NOT DEFINED THIRD_PARTY_DIR)
    set (THIRD_PARTY_DIR ../)
endif ()

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

add_subdirectory(ngtcp2)
target_include_directories(ngtcp2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ngtcp2/lib/includes)
target_include_directories(ngtcp2 PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/ngtcp2/lib/includes)

add_subdirectory(ag_ngtcp2_crypto)
