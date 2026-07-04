#!/bin/sh

# Export the dns-libs recipe at the version reported by `git describe` (e.g.
# `2.8.58` on a tag, or `2.8.58-5-gabc1234` in between). When the package is
# built, conanfile.py checks out the matching commit: a release tag for a plain
# version, or the `-g<rev>` commit for a snapshot. To build uncommitted
# working-tree changes instead, use `conan create . --version local`.
#
# Pass a version (without leading v) as $1 to export that exact release tag.

set -e

cd "$(dirname "$0")/.."

version=$(git describe --tags --match "v*" ${1:+v$1} | sed 's/^v//')
conan export . --user adguard --channel oss --version "$version"
