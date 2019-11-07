project(third_party_nghttp2)

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # too noisy output
    set(ENABLE_DEBUG OFF CACHE BOOL "" FORCE)
endif ()

set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)

add_subdirectory(nghttp2)
target_include_directories(nghttp2_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/nghttp2/lib/includes)
target_include_directories(nghttp2_static PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/nghttp2/lib/includes)
