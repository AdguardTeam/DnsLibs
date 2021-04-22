#!/usr/bin/env python3

import io
import os
import hashlib

WORK_DIR = os.path.dirname(os.path.realpath(__file__))
WIN_INC_DIR = os.path.join(WORK_DIR, 'include')

API_HASH_FILE = os.path.join(WORK_DIR, 'src', 'ag_dns_h_hash.inc')

API_FILES = [
    os.path.join(WIN_INC_DIR, 'ag_dns.h'),
]

file_hash = hashlib.sha256()
for file in sorted(API_FILES):
    print('Processing "{0}"...'.format(file))
    with io.open(file, 'r', encoding='utf-8', errors='ignore') as file_handle:
        for line in file_handle:
            file_hash.update(line.encode('utf-8'))

digest = file_hash.hexdigest()
print('Generated hash: {0}'.format(digest))

with open(API_HASH_FILE, 'r+') as file_handle:
    api_hash_line = '#define AG_DNSLIBS_H_HASH "{0}"\n'.format(digest)
    if api_hash_line not in file_handle.read():
        file_handle.seek(0)
        file_handle.write(api_hash_line)
