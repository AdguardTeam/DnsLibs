cmake_minimum_required(VERSION 3.0)

set(TARGET_OS "macos" CACHE STRING "Target OS")

string(TOLOWER "${TARGET_OS}" TARGET_OS)

message(STATUS "EFFECTIVE_PLATFORM_NAME=$ENV{EFFECTIVE_PLATFORM_NAME}")
set(EFFECTIVE_PLATFORM $ENV{EFFECTIVE_PLATFORM_NAME})

if (EFFECTIVE_PLATFORM STREQUAL "-iphonesimulator")
    set(CMAKE_OSX_SYSROOT iphonesimulator)
    foreach(arch ${CMAKE_OSX_ARCHITECTURES})
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch ${arch}")
    endforeach()

    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.ios")
elseif ("${TARGET_OS}" STREQUAL "macos")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "Minimum macOS deployment version")
    set(CMAKE_ASM_FLAGS "-mmacosx-version-min=10.12")
    foreach(arch ${CMAKE_OSX_ARCHITECTURES})
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch ${arch}")
    endforeach()

    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.macos")
elseif ("${TARGET_OS}" STREQUAL "ios")
    set(CMAKE_SYSTEM_PROCESSOR "arm64")
    set(CMAKE_OSX_ARCHITECTURES "arm64")
    set(CMAKE_SYSTEM_NAME "Darwin")
    set(CMAKE_OSX_SYSROOT iphoneos)
    set(CMAKE_C_COMPILER_ARG1 "-arch ${CMAKE_SYSTEM_PROCESSOR}")
    set(CMAKE_CXX_COMPILER_ARG1 "-arch ${CMAKE_SYSTEM_PROCESSOR}")
    set(CMAKE_XCODE_ATTRIBUTE_BITCODE_GENERATION_MODE bitcode CACHE INTERNAL "")
    set(SDK_NAME_VERSION_FLAGS "-mios-version-min=$ENV{IPHONEOS_DEPLOYMENT_TARGET}")
    add_compile_options(-arch ${CMAKE_SYSTEM_PROCESSOR} -fembed-bitcode)

    string(REPLACE "." ";" VERSION_LIST $ENV{IPHONEOS_DEPLOYMENT_TARGET})
    list(GET VERSION_LIST 0 IOS_VERSION_MAJOR)
    list(GET VERSION_LIST 1 IOS_VERSION_MINOR)
    add_definitions(-DIOS_VERSION_MAJOR=${IOS_VERSION_MAJOR})
    add_definitions(-DIOS_VERSION_MINOR=${IOS_VERSION_MINOR})

    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.ios")
else ()
    message(FATAL_ERROR "unknown os: ${TARGET_OS}")
endif ()


project(dnsproxy_framework)

# Ensure that API is compatible with minimum MacOS version
add_compile_options(-Werror=unguarded-availability)

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)

set(DNS_LIBS_DIR ../../..)

add_compile_options(-fno-strict-aliasing -fno-exceptions -fno-rtti -fobjc-abi-version=2)
add_definitions(-DFMT_EXCEPTIONS=0)

add_library(AGDnsProxy SHARED
    AGDnsProxy.h
    AGDnsProxyEvents.h
    AGDnsProxy.mm
)
set_property(TARGET AGDnsProxy PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(AGDnsProxy PROPERTIES
    FRAMEWORK TRUE
    FRAMEWORK_VERSION A
    VERSION 1.6.32
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
)

if (NOT TARGET dnsproxy)
    add_subdirectory(${DNS_LIBS_DIR}/proxy ${CMAKE_BINARY_DIR}/proxy)
endif ()

target_link_libraries(AGDnsProxy dnsproxy resolv)

if (APPLE)
    target_link_libraries(AGDnsProxy "-framework Foundation" "-framework CoreFoundation" "-framework NetworkExtension")
endif ()

enable_testing()
if (NOT TARGET tests)
    add_custom_target(tests)
endif ()

if("${TARGET_OS}" STREQUAL "macos")
    add_executable(test_AGDnsProxy EXCLUDE_FROM_ALL test_AGDnsProxy.mm)
    target_compile_options(test_AGDnsProxy PRIVATE "-fobjc-arc")
    target_compile_options(test_AGDnsProxy PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_AGDnsProxy
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(test_AGDnsProxy AGDnsProxy)
    add_dependencies(tests test_AGDnsProxy)
    add_test(AGDnsProxyTest test_AGDnsProxy)

    add_executable(test_AGDnsProxyDescriptions EXCLUDE_FROM_ALL test_AGDnsProxyDescriptions.mm)
    target_compile_options(test_AGDnsProxyDescriptions PRIVATE "-fobjc-arc")
    target_compile_options(test_AGDnsProxyDescriptions PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_AGDnsProxyDescriptions
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
    add_dependencies(test_AGDnsProxyDescriptions AGDnsProxy)
    add_dependencies(tests test_AGDnsProxyDescriptions)
    add_test(AGDnsProxyTest test_AGDnsProxyDescriptions)

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

    add_executable(test_ListenerInitError EXCLUDE_FROM_ALL test_ListenerInitError.mm)
    target_compile_options(test_ListenerInitError PRIVATE "-fobjc-arc")
    target_compile_options(test_ListenerInitError PRIVATE -F${CMAKE_CURRENT_BINARY_DIR})
    add_dependencies(test_ListenerInitError AGDnsProxy)
    target_link_libraries(test_ListenerInitError
            "-F${CMAKE_CURRENT_BINARY_DIR}"
            "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}"
            "-framework AGDnsProxy -framework Foundation")
endif()
