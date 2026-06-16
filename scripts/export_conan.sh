#!/bin/sh

set -e

cd "$(dirname "$0")/.."

TAG=$(git describe --abbrev=0 --match=v* ${1:+v$1})

# Export the conanfile as it was at the tag, then restore the working copy.
trap 'git checkout -- conanfile.py' EXIT
git checkout "$TAG" -- conanfile.py
conan export . --user adguard --channel oss --version ${TAG#v}
