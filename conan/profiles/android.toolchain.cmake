# Get ${CMAKE_PLATFORM_INFO_DIR}/../.. and ../../.. . Need to use get_filename_component because CMAKE_PLATFORM_INFO_DIR
# may not be created yet.
get_filename_component(CMAKE_PLATFORM_INFO_DIR_PARENT "${CMAKE_PLATFORM_INFO_DIR}" DIRECTORY)
get_filename_component(CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT "${CMAKE_PLATFORM_INFO_DIR_PARENT}" DIRECTORY)
get_filename_component(CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT "${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}" DIRECTORY)

# Load conan build info
if(EXISTS "${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}/conanbuildinfo.cmake")
include("${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}/conanbuildinfo.cmake")
message("included ${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}/conanbuildinfo.cmake")
elseif(EXISTS "${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT}/conanbuildinfo.cmake")
include("${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT}/conanbuildinfo.cmake")
message("included ${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT}/conanbuildinfo.cmake")
else()
message(FATAL_ERROR "conanbuildinfo.cmake not found, make sure that conan install finished correctly.")
endif()
message("ARCH: ${CONAN_SETTINGS_ARCH}")

if(CONAN_SETTINGS_ARCH STREQUAL armv7)
    set(ANDROID_ABI armeabi-v7a)
    set(ANDROID_PLATFORM 19)
elseif(CONAN_SETTINGS_ARCH STREQUAL armv8)
    set(ANDROID_ABI arm64-v8a)
    set(ANDROID_PLATFORM 21)
elseif(CONAN_SETTINGS_ARCH STREQUAL x86_64)
    set(ANDROID_ABI x86_64)
    set(ANDROID_PLATFORM 21)
elseif(CONAN_SETTINGS_ARCH STREQUAL x86)
    set(ANDROID_ABI x86)
    set(ANDROID_PLATFORM 19)
else()
    message(FATAL_ERROR "Architecture ${CONAN_SETTINGS_ARCH} is not supported")
endif()

if(EXISTS "$ENV{CMAKE_ORIGINAL_TOOLCHAIN}")
message("Including $ENV{CMAKE_ORIGINAL_TOOLCHAIN}")
include("$ENV{CMAKE_ORIGINAL_TOOLCHAIN}")
else()
message(FATAL_ERROR "Please specify valid toolchain in CMAKE_ANDROID_TOOLCHAIN environment variable")
endif()

# Use conan paths instead of NDK paths for find
set(CMAKE_FIND_ROOT_PATH /)
set(CMAKE_FIND_USE_CMAKE_PATH OFF)

# We don't need to export any symbol implicitly, and also disable C++ exceptions, and enable unwind tables.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fno-exceptions -funwind-tables")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fno-exceptions -funwind-tables")
