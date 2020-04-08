project(third_party_curl)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # too noisy output
    set(ENABLE_DEBUG OFF CACHE BOOL "" FORCE)
    set(ENABLE_CURLDEBUG OFF CACHE BOOL "" FORCE)
endif ()

set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(ENABLE_MANUAL OFF CACHE BOOL "" FORCE)
set(HTTP_ONLY ON CACHE BOOL "" FORCE)
set(USE_NGHTTP2 ON CACHE BOOL "" FORCE)
set(CURL_DISABLE_COOKIES ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)

if (NOT TARGET nghttp2_static)
    add_subdirectory(${THIRD_PARTY_DIR}/nghttp2 ${CMAKE_BINARY_DIR}/third-party/nghttp2)
endif ()

if (NOT TARGET boringssl_static)
    add_subdirectory(${THIRD_PARTY_DIR}/boringssl ${CMAKE_BINARY_DIR}/third-party/boringssl)
endif ()

# for FindNGHTTP2
set(NGHTTP2_LIBRARY nghttp2_static)
get_target_property(NGHTTP2_INCLUDE_DIR nghttp2_static INTERFACE_INCLUDE_DIRECTORIES)

function(install)
# install is disabled
endfunction()

include(../../common/apply_patch.cmake)

apply_patch("${CMAKE_CURRENT_SOURCE_DIR}/easy_reuse.patch" "${CMAKE_CURRENT_SOURCE_DIR}/curl")
apply_patch("${CMAKE_CURRENT_SOURCE_DIR}/find_openssl.patch" "${CMAKE_CURRENT_SOURCE_DIR}/curl")
apply_patch("${CMAKE_CURRENT_SOURCE_DIR}/other_tests.patch" "${CMAKE_CURRENT_SOURCE_DIR}/curl")
apply_patch("${CMAKE_CURRENT_SOURCE_DIR}/check_nroff.patch" "${CMAKE_CURRENT_SOURCE_DIR}/curl")
apply_patch("${CMAKE_CURRENT_SOURCE_DIR}/lld_link_manifest.patch" "${CMAKE_CURRENT_SOURCE_DIR}/curl")

add_subdirectory(curl)
