#!/bin/bash

argument_version=$1
if [ -z "$argument_version" ]
then
  NEW_VERSION=$(cat ../platform/android/dnsproxy/lib/build.gradle | grep "version =" | sed -e "s/,.*//g" | sed -e "s/.*://g" | sed -e "s/[' ]//g")
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
