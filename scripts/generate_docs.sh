#!/bin/bash

set -e
set -x

rm -rf ../doc/mac/*
rm -rf ../doc/capi/*
rm -rf ../doc/win/*
rm -rf ../doc/android/*

cp ../platform/windows/capi/test/capi_test.c ../doxyfiles/capi_example.h
echo -e "/**\n@page capi_example Usage example\n@code{.c}\n" | cat - ../doxyfiles/capi_example.h > temp.h && mv temp.h ../doxyfiles/capi_example.h
echo -e "@endcode \n */" >> ../doxyfiles/capi_example.h

doxygen ../doxyfiles/MacDoxyfile
doxygen ../doxyfiles/CApiDoxyfile
doxygen ../doxyfiles/WinDoxyfile
doxygen ../doxyfiles/AndroidDoxyfile

rm -f ../doxyfiles/capi_example.h
