#!/bin/sh

BUILDDIR="${SRCROOT}/ext/build"
FRAMEWORK_DIR="${SRCROOT}/../framework"

if [ "${1}" == "clean" ]; then
    echo "Clean Build"
    rm -Rfv "${BUILDDIR}"
    exit 0
fi

mkdir -pv "${BUILDDIR}"
cd "${BUILDDIR}"
pwd

OPT="-DCMAKE_BUILD_TYPE=Release"
if [ ${CONFIGURATION} == "Debug" ]; then
    OPT="-DCMAKE_BUILD_TYPE=Debug"
fi

cmake ${OPT} ${FRAMEWORK_DIR}
if [ $? != 0 ]; then
    echo "CMake error!"
    exit 1
fi

make -j 4 ${TARGETNAME}
if [ $? != 0 ]; then
    echo "make error!"
    exit 1
fi
