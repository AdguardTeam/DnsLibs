cmake_minimum_required(VERSION 3.6)
project(ngtcp2)

if (NOT DEFINED THIRD_PARTY_DIR)
    set (THIRD_PARTY_DIR ../)
endif ()

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

set(HAVE_SSL_IS_QUIC ON CACHE BOOL "Have symbol SSL_is_quic")
set(HAVE_SSL_SET_QUIC_EARLY_DATA_CONTEXT ON CACHE BOOL "Have symbol SSL_set_quic_early_data_context")
add_compile_options(-DWIN32_LEAN_AND_MEAN=1)
link_libraries(boringssl_static)
add_subdirectory(ngtcp2)
target_include_directories(ngtcp2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ngtcp2/lib/includes)
target_include_directories(ngtcp2 PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/ngtcp2/lib/includes)
