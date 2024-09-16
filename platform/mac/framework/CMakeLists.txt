cmake_minimum_required(VERSION 3.24)
if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "../../../cmake/conan_bootstrap.cmake")
endif()

set(TARGET_OS "macos" CACHE STRING "Target OS")

string(TOLOWER "${TARGET_OS}" TARGET_OS)

message(STATUS "EFFECTIVE_PLATFORM_NAME=$ENV{EFFECTIVE_PLATFORM_NAME}")
set(EFFECTIVE_PLATFORM $ENV{EFFECTIVE_PLATFORM_NAME})


if (CMAKE_OSX_SYSROOT STREQUAL "iphonesimulator")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum iOS deployment version")
    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.ios")
elseif ("${TARGET_OS}" STREQUAL "macos")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum macOS deployment version")
    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.macos")
elseif ("${TARGET_OS}" STREQUAL "ios")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum iOS deployment version")
    set(CMAKE_XCODE_ATTRIBUTE_BITCODE_GENERATION_MODE bitcode CACHE INTERNAL "")
    add_compile_options(-fembed-bitcode)
    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.ios")
else ()
    message(FATAL_ERROR "unknown os: ${TARGET_OS}")
endif ()

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # allows visibility=hidden for static targets for subprojects
cmake_policy(SET CMP0063 NEW) # allows visibility=hidden for static targets for this project
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_OBJC_VISIBILITY_PRESET default)
set(CMAKE_OBJCXX_VISIBILITY_PRESET default)

project(dnsproxy_framework C CXX OBJC OBJCXX)

# Ensure that API is compatible with minimum MacOS version
add_compile_options(-Werror=unguarded-availability)
# Allow framework to be linked into application extension
link_libraries(-Wl,-application_extension)
# TODO: Remove this workaround after updating to XCode 15.1: https://developer.apple.com/documentation/xcode-release-notes/xcode-15-release-notes#Linking
if (CMAKE_CXX_COMPILER_ID MATCHES "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "15.0.0")
    add_link_options(-Wl,-ld_classic)
endif()

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(DNS_LIBS_DIR ../../..)

add_compile_options(-fno-strict-aliasing -fno-exceptions -fobjc-abi-version=2)
add_definitions(-DFMT_EXCEPTIONS=0)

add_library(AGDnsProxy SHARED
    AGDnsProxyEvents.h
    AGDnsProxy.h AGDnsProxy.mm
    AGDnsProxyXPC.h AGDnsProxyXPC.mm
    AGDnsXPCObject.h AGDnsXPCObject.m
    AGDnsProxyModule.h module.modulemap
)
if("${TARGET_OS}" STREQUAL "macos")
    target_sources(AGDnsProxy PRIVATE NSTask+AGUtils.mm)
endif()
set_property(TARGET AGDnsProxy PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(AGDnsProxy PROPERTIES
    FRAMEWORK TRUE
    FRAMEWORK_VERSION A
    VERSION 2.5.46
    MACOSX_FRAMEWORK_INFO_PLIST "${INFOPLIST_FILE}"
    MACOSX_FRAMEWORK_IDENTIFIER com.adguard.dnsproxy
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Developer ID Application: Performiks OOO (N33TQXN8C7)"
    INSTALL_NAME_DIR "@rpath"
    BUILD_WITH_INSTALL_RPATH 1
    COMPILE_FLAGS "-fobjc-arc"
)
set_property(TARGET AGDnsProxy PROPERTY PUBLIC_HEADER
    AGDnsProxy.h
    AGDnsProxyEvents.h
    AGDnsProxyModule.h
    AGDnsProxyXPC.h
    AGDnsXPCObject.h
)
set_property(SOURCE module.modulemap
        PROPERTY MACOSX_PACKAGE_LOCATION "Modules")
if("${TARGET_OS}" STREQUAL "macos")
add_custom_command(TARGET AGDnsProxy POST_BUILD
        COMMAND
        ${CMAKE_COMMAND} -E create_symlink "Versions/Current/Modules" "${CMAKE_BINARY_DIR}/AGDnsProxy.framework/Modules")
endif()

add_definitions(-D_BUILDING_DNSPROXY_FRAMEWORK=1)
if (NOT TARGET dnsproxy)
    add_subdirectory(${DNS_LIBS_DIR}/proxy ${CMAKE_BINARY_DIR}/proxy)
endif ()

find_package(native_libs_common REQUIRED)
target_link_libraries(AGDnsProxy dnsproxy resolv native_libs_common::native_libs_common)

if (APPLE)
    target_link_libraries(AGDnsProxy "-framework Foundation" "-framework CoreFoundation" "-framework NetworkExtension")
endif ()

enable_testing()
if (NOT TARGET tests)
    add_custom_target(tests)
endif ()

function(add_test_target TARGET_NAME SOURCE_FILE)
    add_executable(${TARGET_NAME} EXCLUDE_FROM_ALL ${SOURCE_FILE})
    target_compile_options(${TARGET_NAME} PRIVATE "-fobjc-arc")
    target_compile_options(${TARGET_NAME} PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${TARGET_NAME}
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(${TARGET_NAME} AGDnsProxy)
    add_dependencies(tests ${TARGET_NAME})
    add_test(NAME ${TARGET_NAME}Test COMMAND ${TARGET_NAME})
endfunction()

if("${TARGET_OS}" STREQUAL "macos")
    add_executable(test_AGDnsProxyListenerFailsInit EXCLUDE_FROM_ALL test_AGDnsProxyListenerFailsInit.mm)
    target_compile_options(test_AGDnsProxyListenerFailsInit PRIVATE "-fobjc-arc")
    target_compile_options(test_AGDnsProxyListenerFailsInit PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_AGDnsProxyListenerFailsInit
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(test_AGDnsProxyListenerFailsInit AGDnsProxy)
    add_dependencies(tests test_AGDnsProxyListenerFailsInit)
    add_test(AGDnsProxyListenerFailsInitTest test_AGDnsProxyListenerFailsInit)

    add_executable(test_AGDnsStamp EXCLUDE_FROM_ALL test_AGDnsStamp.mm)
    target_compile_options(test_AGDnsStamp PRIVATE "-fobjc-arc")
    target_compile_options(test_AGDnsStamp PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_AGDnsStamp
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(test_AGDnsStamp AGDnsProxy)
    add_dependencies(tests test_AGDnsStamp)
    add_test(AGDnsStampTest test_AGDnsStamp)

    add_executable(test_BindHelper EXCLUDE_FROM_ALL test_BindHelper.mm)
    target_compile_options(test_BindHelper PRIVATE "-fobjc-arc")
    target_compile_options(test_BindHelper PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    add_dependencies(test_BindHelper AGDnsProxy)
    target_link_libraries(test_BindHelper
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(tests test_BindHelper)

    add_executable(test_ListenerInitError EXCLUDE_FROM_ALL test_ListenerInitError.mm)
    target_compile_options(test_ListenerInitError PRIVATE "-fobjc-arc")
    target_compile_options(test_ListenerInitError PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    add_dependencies(test_ListenerInitError AGDnsProxy)
    target_link_libraries(test_ListenerInitError
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(tests test_ListenerInitError)
    add_test(ListenerInitError test_ListenerInitError)

    add_executable(test_AGDnsProxyHandleMessageAsyncTransparent EXCLUDE_FROM_ALL test_AGDnsProxyHandleMessageAsyncTransparent.mm)
    target_compile_options(test_AGDnsProxyHandleMessageAsyncTransparent PRIVATE "-fobjc-arc")
    target_compile_options(test_AGDnsProxyHandleMessageAsyncTransparent PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    add_dependencies(test_AGDnsProxyHandleMessageAsyncTransparent AGDnsProxy)
    target_link_libraries(test_AGDnsProxyHandleMessageAsyncTransparent
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(tests test_AGDnsProxyHandleMessageAsyncTransparent)
    add_test(ListenerInitError test_AGDnsProxyHandleMessageAsyncTransparent)

    add_executable(test_AGDnsProxyStandalone EXCLUDE_FROM_ALL test_AGDnsProxyStandalone.mm)
    target_compile_options(test_AGDnsProxyStandalone PRIVATE "-fobjc-arc")
    target_compile_options(test_AGDnsProxyStandalone PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_AGDnsProxyStandalone
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(test_AGDnsProxyStandalone AGDnsProxy)
    add_dependencies(tests test_AGDnsProxyStandalone)
endif()
