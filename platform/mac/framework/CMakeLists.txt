cmake_minimum_required(VERSION 3.0)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.14" CACHE STRING "Minimum macOS deployment version")

project(dnsproxy_framework)

# Ensure that API is compatible with minimum MacOS version
add_compile_options(-Werror=unguarded-availability)

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)

set(DNS_LIBS_DIR ../../..)

add_compile_options(-fno-strict-aliasing -fno-exceptions)
add_definitions(-DFMT_EXCEPTIONS=0)

set(CMAKE_ASM_FLAGS "-mmacosx-version-min=10.14")

add_library(AGDnsProxy SHARED AGDnsProxy.h AGDnsProxy.mm)
set_property(TARGET AGDnsProxy PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(AGDnsProxy PROPERTIES
    FRAMEWORK TRUE
    FRAMEWORK_VERSION A
    VERSION 1.0
    MACOSX_FRAMEWORK_IDENTIFIER a.test.adguard
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Developer ID Application: Performiks OOO (N33TQXN8C7)"
)
set_property(TARGET AGDnsProxy PROPERTY PUBLIC_HEADER AGDnsProxy.h)

if (NOT TARGET dnsproxy)
    add_subdirectory(${DNS_LIBS_DIR}/proxy ${CMAKE_BINARY_DIR}/proxy)
endif ()

target_link_libraries(AGDnsProxy dnsproxy)

if (APPLE)
    target_link_libraries(AGDnsProxy "-framework Foundation" "-framework CoreFoundation" "-framework NetworkExtension")
endif ()
