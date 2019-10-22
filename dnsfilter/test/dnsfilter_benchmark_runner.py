#!/usr/bin/python3

import os
import certifi
import zipfile
import urllib.request
import subprocess


BENCH_BINARY_PATH = './dnsfilter_benchmark'

FILTER_LIST_URL = 'https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/gh-pages/Filters/filter.txt'
DOMAINS_BASE_URL = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'

FILTER_LIST_FILE_NAME = 'bench_filter.txt'
DOMAINS_BASE_FILE_NAME = 'bench_domains.txt'


if not os.path.isfile(FILTER_LIST_FILE_NAME):
    print('Downloading filter list from \'' + FILTER_LIST_URL + '\'...')
    with urllib.request.urlopen(FILTER_LIST_URL, cafile=certifi.where()) as page:
        with open('./' + FILTER_LIST_FILE_NAME, 'w') as file:
            file.write(page.read().decode('utf-8'))
    print('Filter list downloaded')

if not os.path.isfile(DOMAINS_BASE_FILE_NAME):
    domains_base_archive = DOMAINS_BASE_URL.split("/")[-1]
    if not os.path.isfile(DOMAINS_BASE_URL):
        print('Downloading domains base from \'' + DOMAINS_BASE_URL + '\'...')
        with urllib.request.urlopen(DOMAINS_BASE_URL, cafile=certifi.where()) as content:
            with open('./' + domains_base_archive, 'wb') as file:
                file.write(content.read())
        print('Domains base downloaded')

    with zipfile.ZipFile('./' + domains_base_archive, 'r') as zip_ref:
        print('Unpacking domains base \'' + domains_base_archive + '\'...')
        zip_ref.extractall('./')
        print('Domains base extracted')

    extracted_base = domains_base_archive
    if domains_base_archive.endswith('.zip'):
        extracted_base = domains_base_archive[:-4]

    os.rename(extracted_base, DOMAINS_BASE_FILE_NAME)

subprocess.call([BENCH_BINARY_PATH, '-f', FILTER_LIST_FILE_NAME, '-d', DOMAINS_BASE_FILE_NAME])
