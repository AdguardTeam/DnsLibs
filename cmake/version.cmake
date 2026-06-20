# Resolves the project version once per CMake run and exposes:
#   DNS_LIBS_VERSION_FULL    full string (1.2.3, 1.2.3-rc.1, 1.2.3-6-gabcdef)
#   DNS_LIBS_VERSION_CORE    numeric core X.Y.Z (prerelease/build suffix dropped)
#   DNS_LIBS_VERSION_COMMAS  core with commas, X,Y,Z (for Win32 RC FILEVERSION)
#
# Source order:
#   1. -DDNS_LIBS_VERSION=<value> cache/var override (conan self.version)
#   2. DNS_LIBS_VERSION environment variable (CI/CD sets it once per job)
#   3. git describe --tags --match v*
#   4. 0.0.0-git fallback (with a warning) so the build never hard-fails.
include_guard(GLOBAL)

if(DEFINED DNS_LIBS_VERSION AND NOT "${DNS_LIBS_VERSION}" STREQUAL "")
    set(_dnslibs_version "${DNS_LIBS_VERSION}")
elseif(NOT "$ENV{DNS_LIBS_VERSION}" STREQUAL "")
    set(_dnslibs_version "$ENV{DNS_LIBS_VERSION}")
else()
    find_package(Git QUIET)
    set(_dnslibs_version "")
    if(GIT_FOUND)
        execute_process(
                COMMAND "${GIT_EXECUTABLE}" describe --tags --match "v*"
                WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.."
                OUTPUT_VARIABLE _dnslibs_describe
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE _dnslibs_git_rc)
        if(_dnslibs_git_rc EQUAL 0 AND NOT "${_dnslibs_describe}" STREQUAL "")
            string(REGEX REPLACE "^v" "" _dnslibs_version "${_dnslibs_describe}")
        endif()
    endif()
    if("${_dnslibs_version}" STREQUAL "")
        set(_dnslibs_version "0.0.0-git")
        message(WARNING "DNS_LIBS: no -DDNS_LIBS_VERSION and git describe unavailable; using ${_dnslibs_version}")
    endif()
endif()

set(DNS_LIBS_VERSION_FULL "${_dnslibs_version}")

# Numeric core = leading X.Y.Z of the full version.
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" DNS_LIBS_VERSION_CORE "${DNS_LIBS_VERSION_FULL}")
if("${DNS_LIBS_VERSION_CORE}" STREQUAL "")
    message(FATAL_ERROR "DNS_LIBS: cannot parse a core X.Y.Z from '${DNS_LIBS_VERSION_FULL}'")
endif()
string(REPLACE "." "," DNS_LIBS_VERSION_COMMAS "${DNS_LIBS_VERSION_CORE}")

message(STATUS "DNS_LIBS version: ${DNS_LIBS_VERSION_FULL} (core ${DNS_LIBS_VERSION_CORE})")
