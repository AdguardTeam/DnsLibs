project(third_party_boringssl)

if (WIN32)
    link_libraries(ws2_32)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=1)
endif()

add_subdirectory(boringssl)

add_library(boringssl_static EXCLUDE_FROM_ALL stub.cpp)
add_library(OpenSSL::Crypto ALIAS boringssl_static)
add_library(OpenSSL::SSL ALIAS boringssl_static)

set(OPENSSL_LIBRARIES "boringssl_static" CACHE STRING "BoringSSL library" FORCE)
set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include" CACHE STRING "BoringSSL include dir" FORCE)
set(OPENSSL_CRYPTO_LIBRARY "boringssl_static" CACHE STRING "BoringSSL library" FORCE)
set(OPENSSL_SSL_LIBRARY "boringssl_static" CACHE STRING "BoringSSL library" FORCE)

target_include_directories(boringssl_static PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(boringssl_static ssl crypto)
