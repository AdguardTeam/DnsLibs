#!/bin/bash
# Stamps the project version across the platform-specific source files that are
# compiled into the build.
#
# Usage:
#   ./scripts/set_version.sh [VERSION]
#
# With no argument the version is derived from `git describe` (the default for
# local builds): on a release tag this yields "1.2.3" or "1.2.3-rc.1", and
# between tags an intermediate description like "1.2.3-6-gabcdef".
#
# The numeric core "X.Y.Z" is written to the fields that accept numbers only
# (the Apple framework CMake VERSION, the Windows FILEVERSION/PRODUCTVERSION and
# the .NET AssemblyVersion/AssemblyFileVersion); the full version string is
# written to every free-form field (the Gradle version name and the Windows
# ProductVersion display string).

set -euo pipefail

# Pick a sed and the matching in-place flag. GNU sed (incl. Homebrew's gsed and
# Git for Windows' sed) accepts "-i"; BSD/macOS sed needs an empty backup suffix.
if sed --version >/dev/null 2>&1; then
    SED_INPLACE=(sed -i)
else
    SED_INPLACE=(sed -i '')
fi

# Move to the repository root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [VERSION]" >&2
    exit 1
fi

# Resolve the new version: an explicit argument wins; otherwise derive it from
# the nearest version tag via git describe.
if [[ $# -eq 1 ]]; then
    new_full=$1
else
    new_full=$(git describe --tags --match 'v*' | sed -e 's/^v//')
fi

# Split into the free-form full string and the numeric core (everything before
# the first '-' or '+'): both "1.2.3-rc.1" and "1.2.3-6-gabcdef" -> core "1.2.3".
new_core=${new_full%%[-+]*}

if ! [[ "${new_full}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*$ ]]; then
    echo "Invalid version format: ${new_full}" >&2
    exit 1
fi
if ! [[ "${new_core}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version core: ${new_core}" >&2
    exit 1
fi

GRADLE=platform/android/dnsproxy/lib/build.gradle

# Current version (full string) and its core, read from the Gradle version name
# so both the free-string and the core-only fields can be matched precisely.
current_full=$(grep "^version =" "${GRADLE}" | sed -e "s/,.*//g" -e "s/.*://g" -e "s/[' ]//g")
current_core=${current_full%%[-+]*}
echo "Version: ${current_full} -> ${new_full} (core ${current_core} -> ${new_core})"

# Android version code: bump by one.
current_code=$(grep "^version =" "${GRADLE}" | sed -e "s/.*code://" -e "s/]//g" -e "s/[ ]//g")
new_code=$((current_code + 1))

# Escaped search patterns: "esc" matches the old full version (free-string
# fields), "esc_core" matches the old numeric core (core-only fields).
esc=$(echo "${current_full}" | sed -e 's/\./\\./g')
esc_core=$(echo "${current_core}" | sed -e 's/\./\\./g')

# Android Gradle: version name (free string) and version code.
"${SED_INPLACE[@]}" "s/name: '${esc}'/name: '${new_full}'/" "${GRADLE}"
"${SED_INPLACE[@]}" "s/code: ${current_code}/code: ${new_code}/" "${GRADLE}"

# Apple framework CMake VERSION (numeric core only).
"${SED_INPLACE[@]}" "s/    VERSION ${esc_core}/    VERSION ${new_core}/" platform/mac/framework/CMakeLists.txt

# Windows resource versions: FILEVERSION/PRODUCTVERSION are numeric (commas);
# the ProductVersion string is free-form.
old_commas=${current_core//./,}
new_commas=${new_core//./,}
RC=platform/windows/capi/src/ag_dns.rc
"${SED_INPLACE[@]}" "s/FILEVERSION ${old_commas},0/FILEVERSION ${new_commas},0/" "${RC}"
"${SED_INPLACE[@]}" "s/PRODUCTVERSION ${old_commas},0/PRODUCTVERSION ${new_commas},0/" "${RC}"
"${SED_INPLACE[@]}" "s/\"ProductVersion\", \"${esc}\"/\"ProductVersion\", \"${new_full}\"/" "${RC}"

# .NET assembly versions (numeric core only).
CS=platform/windows/cs/Adguard.Dns/SolutionInfo.cs
"${SED_INPLACE[@]}" "s/AssemblyVersion(\"${esc_core}\")/AssemblyVersion(\"${new_core}\")/" "${CS}"
"${SED_INPLACE[@]}" "s/AssemblyFileVersion(\"${esc_core}\")/AssemblyFileVersion(\"${new_core}\")/" "${CS}"

echo "Version updated: ${new_full} (core ${new_core})"
