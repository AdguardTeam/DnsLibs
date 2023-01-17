#!/usr/bin/env python3

import os
import subprocess
import sys

import yaml

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)
commit_hash_version = "777"

with open(os.path.join(project_dir, "conandata.yml"), "r") as file:
    yaml_data = yaml.safe_load(file)

versions = []
checkout_original_branch = False
if len(sys.argv) > 1:
    checkout_original_branch = True
    versions.append(sys.argv[1])
else:
    versions.append(commit_hash_version)
    for version in yaml_data["commit_hash"]:
        versions.append(version)

for version in versions:
    if version == commit_hash_version:
        subprocess.run(["git", "checkout", "-B", "master", "origin/master"], check=True)
    else:
        hash1 = yaml_data["commit_hash"][version]["hash"]
        the_hash = subprocess.run(["git", "log", "--reverse", "--ancestry-path", hash1 + "..master", "--pretty=%h"],
                                  check=True, capture_output=True, text=True).stdout.splitlines()[0]
        print("HASH is ", the_hash)
        subprocess.run(["git", "checkout", the_hash], check=True)
    subprocess.run(["conan", "export", project_dir, "dns-libs/" + version + "@AdguardTeam/NativeLibsCommon"],
                   check=True)
    if checkout_original_branch:
        subprocess.run(["git", "checkout", "-"], check=True)
