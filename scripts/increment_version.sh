#!/bin/bash
# Increments project version across all platform-specific files
# and appends a new entry to conandata.yml.

set -e

case $(uname) in
Darwin) SED=gsed ;;
*) SED=sed ;;
esac

increment_version() {
  major=${1%%.*}
  minor=$(echo ${1#*.} | ${SED} -e "s/\.[0-9]*//")
  revision=${1##*.}
  echo ${major}.${minor}.$((revision+1))
}

# Move to the repository root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

CURRENT_VERSION=$(grep "^version =" platform/android/dnsproxy/lib/build.gradle \
  | ${SED} -e "s/,.*//g" -e "s/.*://g" -e "s/[' ]//g")
echo "Current version is ${CURRENT_VERSION}"

argument_version=$1
if [ -z "$argument_version" ]; then
  NEW_VERSION=$(increment_version "${CURRENT_VERSION}")
elif [[ "$argument_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  NEW_VERSION=$argument_version
else
  echo "INVALID VERSION FORMAT: ${argument_version}" >&2
  exit 1
fi
echo "New version is ${NEW_VERSION}"

# Android version code is derived from build.gradle and is incremented by 1.
CURRENT_VERSION_CODE=$(grep "^version =" platform/android/dnsproxy/lib/build.gradle \
  | ${SED} -e "s/.*code://" -e "s/]//g" -e "s/[ ]//g")
echo "Current version code is ${CURRENT_VERSION_CODE}"
NEW_VERSION_CODE=$((CURRENT_VERSION_CODE+1))
echo "New version code is ${NEW_VERSION_CODE}"

esc=$(echo "${CURRENT_VERSION}" | ${SED} -e 's/\./\\./g')

${SED} -i "s/name: '${esc}/name: '${NEW_VERSION}/" platform/android/dnsproxy/lib/build.gradle
${SED} -i "s/code: ${CURRENT_VERSION_CODE}/code: ${NEW_VERSION_CODE}/" platform/android/dnsproxy/lib/build.gradle
${SED} -i "s/    VERSION ${esc}/    VERSION ${NEW_VERSION}/" platform/mac/framework/CMakeLists.txt
${SED} -i "s/VERSION ${CURRENT_VERSION//./,},0/VERSION ${NEW_VERSION//./,},0/" platform/windows/capi/src/ag_dns.rc
${SED} -i "s/\"ProductVersion\", \"${esc}/\"ProductVersion\", \"${NEW_VERSION}/" platform/windows/capi/src/ag_dns.rc
${SED} -i "s/Version(\"${esc}/Version(\"${NEW_VERSION}/" platform/windows/cs/Adguard.Dns/SolutionInfo.cs

${SED} -i -e "3{/^## /b;s/^/## ${NEW_VERSION}\n\n/}" CHANGELOG.md

# Append the new version entry to conandata.yml using the master HEAD hash.
COMMIT_HASH=$(git rev-parse HEAD)
echo "Commit hash for ${NEW_VERSION} is ${COMMIT_HASH}"
printf "  \"%s\":\n    hash: \"%s\"\n" "${NEW_VERSION}" "${COMMIT_HASH}" >> conandata.yml
