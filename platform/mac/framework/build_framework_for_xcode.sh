#!/bin/sh

# Builds the AGDnsProxy framework for the platform and architecture Xcode is
# currently targeting and puts it at
#
#     ${PROJECT_DIR}/framework/build/${PLATFORM_NAME}/AGDnsProxy.framework
#
# which is the directory the sample Xcode project (`platform/mac/DnsLibsTestApp`)
# looks for the framework in (FRAMEWORK_SEARCH_PATHS).
# The project links the framework with `-framework AGdnsProxy` and embeds it
# with its own build phases instead of referencing it as a file, because Xcode
# resolves and enumerates referenced frameworks while planning a build, i.e.
# before any build phase has a chance to build them.
#
# The script is meant to be called from an Xcode build phase, so it takes
# everything it needs from the Xcode environment (`PLATFORM_NAME`, `ARCHS`,
# `PROJECT_DIR`, ...). It can also be called by hand, see `--help`.
#
# Every slice is built in its own CMake build directory
# (${PROJECT_DIR}/framework/build) so that switching destinations in Xcode does
# not invalidate the CMake cache of the other slices, and repeated builds are
# incremental.

set -e
set -u

FRAMEWORK_DIR="$(cd "$(dirname "$0")" && pwd)"

HELP_MSG="
Usage: build_framework_for_xcode.sh [options...]
    --platform <name>   Platform to build for: macosx, iphoneos or iphonesimulator.
                        Defaults to \${PLATFORM_NAME} (set by Xcode).
    --arch <name>       Architecture to build for. Defaults to \${ARCHS} (set by
                        Xcode) or to the host architecture.
    --bp <path>         Framework output directory. Defaults to
                        \${PROJECT_DIR}/framework (set by Xcode).
    --debug             Build the framework with the Debug configuration instead
                        of the default RelWithDebInfo one. Note that this also
                        requires Debug builds of the Conan dependencies, which
                        are not what the other workflows populate the local
                        Conan cache with.
    --help              Show this message.
"

PROJECT_DIR="${PROJECT_DIR:-}"
PLATFORM="${PLATFORM_NAME:-}"
ARCH="$(echo "${ARCHS:-}" | xargs)"
BUILD_DIR=""
# The framework is a dependency of the sample app, and its configuration is
# deliberately independent from the app's: the app is built in Debug by default,
# while a Debug framework would require building all Conan dependencies from
# source. RelWithDebInfo carries debug information anyway, so the framework
# stays debuggable from the app.
BUILD_TYPE="RelWithDebInfo"

while [ $# -gt 0 ]; do
    case "$1" in
    --help)
        echo "${HELP_MSG}"
        exit 0
        ;;
    --platform)
        shift
        PLATFORM="${1:-}"
        ;;
    --arch)
        shift
        ARCH="${1:-}"
        ;;
    --bp)
        shift
        BUILD_DIR="${1:-}"
        ;;
    --debug)
        BUILD_TYPE="Debug"
        ;;
    *)
        echo "unknown option ${1}"
        echo "${HELP_MSG}"
        exit 1
        ;;
    esac
    shift
done

if [ -z "${PLATFORM}" ]; then
    echo "error: no platform, pass --platform or run from Xcode" >&2
    echo "${HELP_MSG}"
    exit 1
fi

case "${PLATFORM}" in
macosx | iphoneos | iphonesimulator)
    ;;
*)
    echo "error: unsupported platform ${PLATFORM}" >&2
    echo "${HELP_MSG}"
    exit 1
    ;;
esac

# Xcode builds the host architecture when it builds a single architecture, so
# that is the right default both for macOS and for the iOS simulator.
if [ -z "${ARCH}" ]; then
    ARCH="$(uname -m)"
fi

# Conan dependencies are built for a single architecture, and a framework that
# combines several of them into a universal one cannot be signed with the
# current Xcode, so the sample project builds for the active architecture only.
if [ "$(echo "${ARCH}" | wc -w | xargs)" -ne 1 ]; then
    echo "error: the AGDnsProxy framework can only be built for one architecture, got '${ARCH}'" >&2
    echo "Build the sample app for the active architecture (ONLY_ACTIVE_ARCH=YES)." >&2
    exit 1
fi

if [ -z "${BUILD_DIR}" ]; then
    if [ -z "${PROJECT_DIR}" ]; then
        echo "error: no output directory, pass --bp or run from Xcode" >&2
        echo "${HELP_MSG}"
        exit 1
    fi
    BUILD_DIR="${PROJECT_DIR}/framework"
fi

# `xcodebuild clean` must not spend time on the framework build.
if [ "${ACTION:-}" = "clean" ]; then
    echo "clean: skipping the ${PLATFORM} framework build"
    exit 0
fi

# Xcode runs build phases with its own PATH, not the PATH of an interactive
# shell, so the tools below are not visible when they come from Homebrew, pipx,
# or a similar per-user install, and the build fails with "cmake: command not
# found" even though the same build works from a terminal. Look in the usual
# install locations, and in whatever DNSLIBS_TOOL_PATH points at (a build
# setting, e.g. `xcodebuild DNSLIBS_TOOL_PATH=/opt/tools/bin ... build`).
TOOL_DIRS="${DNSLIBS_TOOL_PATH:-}"
for dir in \
    /opt/homebrew/bin \
    /usr/local/bin \
    "${HOME:-}/.local/bin" \
    "${HOME:-}"/Library/Python/*/bin \
    /Applications/CMake.app/Contents/bin; do
    TOOL_DIRS="${TOOL_DIRS:+${TOOL_DIRS}:}${dir}"
done

EXTRA_PATH=""
OLD_IFS="${IFS}"
IFS=:
for dir in ${TOOL_DIRS}; do
    [ -d "${dir}" ] || continue
    case ":${PATH}:${EXTRA_PATH}:" in
    *":${dir}:"*) continue ;;
    esac
    EXTRA_PATH="${EXTRA_PATH:+${EXTRA_PATH}:}${dir}"
done
IFS="${OLD_IFS}"
unset OLD_IFS TOOL_DIRS dir
PATH="${EXTRA_PATH:+${EXTRA_PATH}:}${PATH}"
unset EXTRA_PATH
export PATH

MISSING_TOOLS=""
for tool in cmake ninja conan; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        MISSING_TOOLS="${MISSING_TOOLS} ${tool}"
    fi
done
if [ -n "${MISSING_TOOLS}" ]; then
    echo "error: missing tool(s):${MISSING_TOOLS}" >&2
    echo "Xcode build phases do not inherit the PATH of your shell, so the tools must be installed" >&2
    echo "in a standard location (/opt/homebrew/bin, /usr/local/bin, ~/.local/bin), e.g.:" >&2
    echo "    brew install cmake ninja && pipx install conan" >&2
    echo "Alternatively, set the DNSLIBS_TOOL_PATH build setting to the directory that holds them:" >&2
    echo "    xcodebuild DNSLIBS_TOOL_PATH=/opt/tools/bin ... build" >&2
    exit 1
fi

case "${PLATFORM}" in
macosx)
    SLICE="macos-${ARCH}"
    ;;
iphoneos)
    # Device builds are arm64-only.
    SLICE="ios"
    ;;
iphonesimulator)
    SLICE="iphonesimulator-${ARCH}"
    ;;
esac

# A CMake build directory belongs to a single configuration: the Conan
# generator files of one build type cannot be reused by another one. The
# default configuration keeps the plain slice name.
if [ "${BUILD_TYPE}" = "RelWithDebInfo" ]; then
    CONFIG_SUFFIX=""
else
    CONFIG_SUFFIX="-${BUILD_TYPE}"
fi

SLICE_DIR="${BUILD_DIR}/build/${SLICE}${CONFIG_SUFFIX}"
OUT_DIR="${BUILD_DIR}/build/${PLATFORM}"

# Several targets link the framework, so their build phases may run in parallel
# and must not drive the same CMake build directory concurrently.
mkdir -p "${BUILD_DIR}"
LOCK_DIR="${BUILD_DIR}/.build_framework_for_xcode.lock"
WAITED=0
while ! mkdir "${LOCK_DIR}" 2>/dev/null; do
    if [ -n "$(find "${LOCK_DIR}" -maxdepth 0 -mmin +15 2>/dev/null)" ]; then
        echo "removing stale lock ${LOCK_DIR}"
        rm -rf "${LOCK_DIR}"
        continue
    fi
    if [ "${WAITED}" -ge 900 ]; then
        echo "error: timed out waiting for ${LOCK_DIR}" >&2
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
trap 'rmdir "${LOCK_DIR}" 2>/dev/null || true' EXIT INT TERM

echo "Building AGDnsProxy for ${SLICE} in ${SLICE_DIR}"
# build_dnsproxy_framework.sh derives the build type from CONFIGURATION.
CONFIGURATION="${BUILD_TYPE}" \
    "${FRAMEWORK_DIR}/build_dnsproxy_framework.sh" \
    --os "${SLICE}" \
    --tn AGDnsProxy \
    --bp "${SLICE_DIR}" \
    --fwp "${FRAMEWORK_DIR}"

# Publish the framework where the Xcode project looks for it.
rm -rf "${OUT_DIR}.tmp"
mkdir -p "${OUT_DIR}.tmp"
cp -R "${SLICE_DIR}/AGDnsProxy.framework" "${OUT_DIR}.tmp"
rm -rf "${OUT_DIR}"
mv "${OUT_DIR}.tmp" "${OUT_DIR}"

echo "AGDnsProxy for ${PLATFORM} (${SLICE}) is available at ${OUT_DIR}/AGDnsProxy.framework"
