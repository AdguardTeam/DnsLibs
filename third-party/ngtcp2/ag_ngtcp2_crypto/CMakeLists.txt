cmake_minimum_required(VERSION 3.6)
project(ag_ngtcp2_crypto)

add_definitions(-DBUILDING_NGTCP2)

set(ag_ngtcp2_crypto_openssl_SOURCES
        openssl/openssl.c
        shared.c
        )

set(ag_ngtcp2_crypto_openssl_INCLUDE_DIRS
        #"${CMAKE_CURRENT_SOURCE_DIR}/../ngtcp2/lib"
        "${CMAKE_CURRENT_SOURCE_DIR}/includes"
        "${CMAKE_CURRENT_BINARY_DIR}/includes"
        )

add_library(ag_ngtcp2_crypto_openssl EXCLUDE_FROM_ALL ${ag_ngtcp2_crypto_openssl_SOURCES})
set_target_properties(ag_ngtcp2_crypto_openssl PROPERTIES
        C_VISIBILITY_PRESET hidden
        POSITION_INDEPENDENT_CODE ON
        )

target_include_directories(ag_ngtcp2_crypto_openssl PUBLIC ${ag_ngtcp2_crypto_openssl_INCLUDE_DIRS})
target_compile_definitions(ag_ngtcp2_crypto_openssl PUBLIC "-DNGTCP2_STATICLIB")
target_link_libraries(ag_ngtcp2_crypto_openssl boringssl_static ngtcp2)
