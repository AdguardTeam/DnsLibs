project(third_party_boringssl)

if (WIN32)
link_libraries(ws2_32)
endif()
add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
add_subdirectory(boringssl)

set(OPENSSL_LIBRARIES "boringssl_static" CACHE STRING "BoringSSL library" FORCE)
set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include" CACHE STRING "BoringSSL include dir" FORCE)
add_library(boringssl_static EXCLUDE_FROM_ALL stub.cpp)
target_include_directories(boringssl_static PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(boringssl_static ssl crypto)
