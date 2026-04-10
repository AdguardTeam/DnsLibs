#!/usr/bin/env python3

"""
This script intended to fill the local conan cache with the packages required
for building the project. Clean build scenario requires running this script
before running the cmake command. Besides that, it may be also required after
the dependencies updates.

Usage:
    bootstrap_conan_deps.py [nlc_url]

`nlc_url` is the URL of AdGuard's NativeLibsCommon repository
(defaults to https://github.com/AdguardTeam/NativeLibsCommon.git).
"""

import os
import shutil
import stat
import subprocess
import sys
import yaml

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)
nlc_url = sys.argv[1] if len(sys.argv) > 1 else 'https://github.com/AdguardTeam/NativeLibsCommon.git'
nlc_dir_name = "native-libs-common"
nlc_versions = []


def on_rm_tree_error(func, path, _):
    """
    Workaround for Windows behavior, where `shutil.rmtree`
    fails with an access error (read only file).
    So, attempt to add write permission and try again.
    """
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


def remove_dir_if_exists(dir_path):
    """Remove a directory if it exists, handling read-only files on Windows."""
    if os.path.exists(dir_path):
        os.chdir(work_dir)
        shutil.rmtree(dir_path, onerror=on_rm_tree_error)


with open(os.path.join(project_dir, "conanfile.py"), "r") as file:
    for line in map(str.strip, file.readlines()):
        if line.startswith('self.requires("native_libs_common/') \
                and ('@adguard/oss"' in line):
            nlc_versions.append(line.split('@')[0].split('/')[1])

os.chdir(work_dir)
nlc_dir = os.path.join(work_dir, nlc_dir_name)
remove_dir_if_exists(nlc_dir)
try:
    subprocess.run(["git", "clone", nlc_url, nlc_dir], check=True)
    os.chdir(nlc_dir)

    # Reduce the chances of missing a necessary dependency exported with NLC
    # by exporting all recipes from all versions of NLC, starting with the minimum
    # necessary.
    min_nlc_version = min(nlc_versions)
    with open("conandata.yml", "r") as file:
        items = yaml.safe_load(file)["commit_hash"]

    for v in nlc_versions: # [k for k in items.keys() if k >= min_nlc_version]:
        subprocess.run(["git", "checkout", "master"], check=True)
        try:
            subprocess.run(["python3", os.path.join(nlc_dir, "scripts", "export_conan.py"), v], check=True)
        except:
            if v in nlc_versions:
                raise
            else:
                # Some native_libs_common versions have broken Conan recipes: ignore them.
                continue
finally:
    remove_dir_if_exists(nlc_dir)
