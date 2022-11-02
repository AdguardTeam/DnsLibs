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
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum macOS deployment version")
    set(CMAKE_ASM_FLAGS "-mmacosx-version-min=10.13")
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
link_libraries(-Wl,-application_extension)

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(DNS_LIBS_DIR ../../..)

add_compile_options(-fno-strict-aliasing -fno-exceptions -fobjc-abi-version=2)
add_definitions(-DFMT_EXCEPTIONS=0)

add_library(AGDnsProxy SHARED
    AGDnsProxy.h
    AGDnsProxyEvents.h
    AGDnsProxy.mm
    module.modulemap
)
if("${TARGET_OS}" STREQUAL "macos")
    target_sources(AGDnsProxy PRIVATE NSTask+AGTimeout.mm)
endif()
set_property(TARGET AGDnsProxy PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(AGDnsProxy PROPERTIES
    FRAMEWORK TRUE
    FRAMEWORK_VERSION A
    VERSION 2.0.37
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
set_property(SOURCE module.modulemap
        PROPERTY MACOSX_PACKAGE_LOCATION "Modules")
if("${TARGET_OS}" STREQUAL "macos")
add_custom_command(TARGET AGDnsProxy POST_BUILD
        COMMAND
        ${CMAKE_COMMAND} -E create_symlink "Versions/Current/Modules" "${CMAKE_BINARY_DIR}/AGDnsProxy.framework/Modules")
endif()

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
