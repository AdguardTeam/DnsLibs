#!/bin/sh

HELP_MSG="
Usage: build_dnsproxy_framework.sh [options...|clean]
    --os       Target os (valid values: macos-{x86_64,arm64}, ios, iphonesimulator-{x86_64,arm64}, all)
               'all' - by default
    --tn       Target framework name
    --iosv     iOS SDK version (devided by dot: e.g., 13.0)
    --bp       Build directory path
    --fwp      Framework cmake project path
    --debug    Build with debug configuration
"

TARGET_OS="all"
BUILD_DIR="${SRCROOT}/framework"
FRAMEWORK_DIR="${SRCROOT}/../framework"

if [ -z ${TARGETNAME+x} ]; then
    TARGET_NAME="AGDnsProxy"
else
    TARGET_NAME="${TARGETNAME}"
fi

if [ "${CONFIGURATION}" = "Debug" ]; then
    BUILD_TYPE="Debug"
else
    BUILD_TYPE="RelWithDebInfo"
fi


if [ "${1}" == "clean" ]; then
    echo "Clean Build"
    rm -Rfv "${BUILD_DIR}"
    exit 0
fi


while [[ $# -gt 0 ]]
do
    case "$1" in
    --help)
        echo "${HELP_MSG}"
        exit 0
        ;;
    --os)
        shift
        if [[ $# -gt 0 ]]; then
            TARGET_OS=$1
        else
            echo "os is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --tn)
        shift
        if [[ $# -gt 0 ]]; then
            TARGET_NAME=$1
        else
            echo "target name is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --iosv)
        shift
        if [[ $# -gt 0 ]]; then
            IOS_SDK_VERSION=$1
        else
            echo "ios version is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --bp)
        shift
        if [[ $# -gt 0 ]]; then
            BUILD_DIR="$1"
        else
            echo "build path is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --fwp)
        shift
        if [[ $# -gt 0 ]]; then
            FRAMEWORK_DIR="$1"
        else
            echo "framework path is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --debug)
        shift
        BUILD_TYPE="Debug"
        ;;
    *)
        echo "unknown option ${1}"
        echo "${HELP_MSG}"
        exit 1
    esac
done


function build_target() {
    local 'target_name' 'target_os' 'build_dir' 'cmake_opt' 'target_arch'

    target_name=$1
    target_os=${2%-*}
    target_arch=${2#*-}
    build_dir=$3

    echo "Building ${target_name}..."

    mkdir -pv "${build_dir}"
    cd "${build_dir}"
    pwd

    if [ ! -f "${build_dir}/CMakeCache.txt" ]; then
        cp "${FRAMEWORK_DIR}/cmake-cache-${target_os}-${target_arch}.txt" "${build_dir}/CMakeCache.txt"
    fi

    if [ "${target_os}" == "ios" ] && [ -z ${IPHONEOS_DEPLOYMENT_TARGET+x} ]; then
        if [ -z ${IOS_SDK_VERSION+x} ]; then
            echo "iOS SDK version should be set"
            exit 1
        fi
        export IPHONEOS_DEPLOYMENT_TARGET="${IOS_SDK_VERSION}"
    elif [ "${target_os}" == "iphonesimulator" ]; then
        export EFFECTIVE_PLATFORM_NAME="-iphonesimulator"
    fi

    target_name=${target_name%-*}
    echo "target_name=${target_name}"
    echo "target_os=${target_os}"

    cmake_opt="-DCMAKE_BUILD_TYPE=${BUILD_TYPE} -GNinja"
    cmake_opt="${cmake_opt} -DCMAKE_XCODE_ATTRIBUTE_DEBUG_INFORMATION_FORMAT=\"dwarf-with-dsym\""
    cmake_opt="${cmake_opt} -DTARGET_OS:STRING=${target_os} -DCMAKE_OSX_ARCHITECTURES=${target_arch}"

    cmake ${cmake_opt} ${FRAMEWORK_DIR}
    if [ $? != 0 ]; then
        echo "CMake error!"
        exit 1
    fi

    ninja ${target_name}
    if [ $? != 0 ]; then
        echo "make error!"
        exit 1
    fi

    cd -

    echo "Built ${target_name} successfully"
}


if [ ! -z ${TARGET_OS+x} ] && [ "${TARGET_OS}" != "all" ]
then
    build_target "${TARGET_NAME}" "${TARGET_OS}" "${BUILD_DIR}"
else
    targets=( macos-x86_64 macos-arm64 ios-arm64 iphonesimulator-x86_64 iphonesimulator-arm64 )
    for i in "${!targets[@]}"
    do
        target=${targets[$i]}
        build_target "${TARGET_NAME}" "${target}" "${BUILD_DIR}/framework-${target}"
    done

    rm -rf "${BUILD_DIR}/${TARGET_NAME}.xcframework"
    rm -rf "${BUILD_DIR}/${TARGET_NAME}.dSYMs"
    rm -rf "${BUILD_DIR}/framework-macos"
    rm -rf "${BUILD_DIR}/framework-iphonesimulator"

    mkdir -p "${BUILD_DIR}/framework-macos"
    cp -Rf "${BUILD_DIR}/framework-macos-x86_64/AGDnsProxy.framework" "${BUILD_DIR}/framework-macos/"
    rm "${BUILD_DIR}"/framework-macos/AGDnsProxy.framework/Versions/A/AGDnsProxy
    lipo -create -output "${BUILD_DIR}"/framework-macos{,-x86_64,-arm64}/AGDnsProxy.framework/Versions/A/AGDnsProxy
    mkdir -p "${BUILD_DIR}/framework-iphonesimulator"
    cp -Rf "${BUILD_DIR}/framework-iphonesimulator-x86_64/AGDnsProxy.framework" "${BUILD_DIR}/framework-iphonesimulator/"
    rm "${BUILD_DIR}"/framework-iphonesimulator/AGDnsProxy.framework/AGDnsProxy
    lipo -create -output "${BUILD_DIR}"/framework-iphonesimulator{,-x86_64,-arm64}/AGDnsProxy.framework/AGDnsProxy

    xcodebuild -create-xcframework -framework "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework" \
        -framework "${BUILD_DIR}/framework-ios-arm64/${TARGET_NAME}.framework" \
        -framework "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework" \
        -output "${BUILD_DIR}/${TARGET_NAME}.xcframework"

    mkdir -p ${BUILD_DIR}/${TARGET_NAME}.dSYMs
    for fw in ${BUILD_DIR}/${TARGET_NAME}.xcframework/*/${TARGET_NAME}.framework; do
        ARCH_AS_IN_XCF=`echo "${fw}" | sed -ne 's|.*/\([^/]*\)/[^/]*.framework$|\1|p'`
        dsymutil -o "${BUILD_DIR}/${TARGET_NAME}.dSYMs/${TARGET_NAME}.framework.${ARCH_AS_IN_XCF}.dSYM" "${fw}/${TARGET_NAME}"
    done
fi
