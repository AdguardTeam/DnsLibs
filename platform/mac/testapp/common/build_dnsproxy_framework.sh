#!/bin/sh

TARGET_OS="macos"
BUILDDIR="${SRCROOT}/framework"
FRAMEWORK_DIR="${SRCROOT}/../framework"

if [ "${1}" == "clean" ]; then
    echo "Clean Build"
    rm -Rfv "${BUILDDIR}"
    exit 0
fi

while [[ $# -gt 0 ]]
do
    case "$1" in
    --os)
        shift
        if [[ $# -gt 0 ]]; then
            TARGET_OS=$1
        else
            echo "no os specified"
            exit 1
        fi
        shift
        ;;
    *)
        echo "unknown option ${1}"
        exit 1
    esac
done

mkdir -pv "${BUILDDIR}"
cd "${BUILDDIR}"
pwd

TARGETNAME=${TARGETNAME%-*}
echo "TARGETNAME=${TARGETNAME}"
echo "TARGET_OS=${TARGET_OS}"

OPT="-DCMAKE_BUILD_TYPE=Release"
if [ ${CONFIGURATION} == "Debug" ]; then
    OPT="-DCMAKE_BUILD_TYPE=Debug"
fi
OPT="${OPT} -DTARGET_OS:STRING=${TARGET_OS}"

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
