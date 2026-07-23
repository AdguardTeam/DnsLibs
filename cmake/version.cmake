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

# The three outputs are published as internal cache entries rather than plain
# variables: include_guard(GLOBAL) turns every include after the first into a
# no-op, so a directory scope that includes this file second (tools/adyg, which
# is added after common) would otherwise see nothing. Cache entries are visible
# in every scope, and the unconditional set() rewrites them on each configure,
# so the version never goes stale.
set(DNS_LIBS_VERSION_FULL "${_dnslibs_version}" CACHE INTERNAL "DNS libs version, full string")

# Numeric core = leading X.Y.Z of the full version.
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" _dnslibs_version_core "${DNS_LIBS_VERSION_FULL}")
if("${_dnslibs_version_core}" STREQUAL "")
    message(FATAL_ERROR "DNS_LIBS: cannot parse a core X.Y.Z from '${DNS_LIBS_VERSION_FULL}'")
endif()
set(DNS_LIBS_VERSION_CORE "${_dnslibs_version_core}" CACHE INTERNAL "DNS libs version, core X.Y.Z")
string(REPLACE "." "," _dnslibs_version_commas "${DNS_LIBS_VERSION_CORE}")
set(DNS_LIBS_VERSION_COMMAS "${_dnslibs_version_commas}" CACHE INTERNAL "DNS libs version, core with commas")

message(STATUS "DNS_LIBS version: ${DNS_LIBS_VERSION_FULL} (core ${DNS_LIBS_VERSION_CORE})")
