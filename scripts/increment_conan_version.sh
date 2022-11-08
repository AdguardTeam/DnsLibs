#!/bin/bash

increment_version() {
  major=${1%%.*}
  minor=$(echo ${1#*.} | sed -e "s/\.[0-9]*//")
  revision=${1##*.}
  echo ${major}.${minor}.$((revision+1))
}

argument_version=$1
if [ -z "$argument_version" ]
then
  VERSION=$(cat ../platform/android/dnsproxy/lib/build.gradle | grep "version =" | sed -e "s/,.*//g" | sed -e "s/.*://g" | sed -e "s/[' ]//g")
  echo "Last version was ${VERSION}"
  NEW_VERSION=$(increment_version ${VERSION})
  echo "New version is ${NEW_VERSION}"
else
  if [[ "$argument_version" =~ ^[0-9]\.[0-9].[0-9]*$ ]]
  then
    NEW_VERSION=$1
    echo "New version is ${NEW_VERSION}"
  else
    echo "INVALID VERSION FORMAT"
  fi
fi

COMMIT_HASH=$(git rev-parse master)
echo "Last commit hash is ${COMMIT_HASH}"

[[ ! -z "$NEW_VERSION" ]] && (printf "  \"${NEW_VERSION}\":\n    hash: \"${COMMIT_HASH}\"\n" | tee -a ../conandata.yml)
