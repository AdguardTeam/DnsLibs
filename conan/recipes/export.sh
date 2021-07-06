#!/bin/sh

for RECIPE_DIR in $(find . -type d -maxdepth 1 -mindepth 1); do
    conan export "$RECIPE_DIR" AdguardTeam/DnsLibs
done
