#!/bin/bash

set -e
set -x

rm -rf ../doc/mac/*
rm -rf ../doc/capi/*
rm -rf ../doc/win/*

doxygen ../doxyfiles/MacDoxyfile
doxygen ../doxyfiles/CApiDoxyfile
doxygen ../doxyfiles/WinDoxyfile