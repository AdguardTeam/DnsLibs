# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html
cmake_minimum_required(VERSION 3.24)
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "../../../../cmake/conan_bootstrap.cmake")
project(jni C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # allows visibility=hidden for static targets for subprojects
cmake_policy(SET CMP0063 NEW) # allows visibility=hidden for static targets for this project
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_compile_options(-fno-strict-aliasing -fno-exceptions)

set(DNS_LIBS_DIR ../../../..)

add_library(adguard-dns SHARED
        src/main/cpp/android_dnsproxy.cpp
        src/main/cpp/jni_utils.cpp
        src/main/cpp/android_dnsstamp.cpp
        src/main/cpp/android_context_manager.cpp
        )

if (NOT TARGET dnsproxy)
    add_subdirectory(${DNS_LIBS_DIR}/proxy ${CMAKE_BINARY_DIR}/proxy)
endif ()
target_link_libraries(adguard-dns dnsproxy)

if (ANDROID)
    target_link_libraries(adguard-dns android log)
endif ()

if (NOT ANDROID)
    find_package(JNI)
    target_include_directories(adguard-dns PUBLIC ${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
endif ()

set_property(TARGET adguard-dns PROPERTY COMPILE_FLAGS "-Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter")
