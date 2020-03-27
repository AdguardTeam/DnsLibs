#!/bin/bash

alias convert_cache="sed -ne '/\/\//{N;/INTERNAL/{/CMAKE/!s|//\(.*\)\n\(.*\):\(.*\)=\(.*\)|    set(\2 \"\4\" CACHE \3 \"\1\")|gp;};}'"

(
echo "if (WIN32)"
  convert_cache booster-data/win32.txt
echo 'elseif (ANDROID_ABI MATCHES "arm64-v8a")'
  convert_cache booster-data/android-arm64.txt
echo 'elseif (ANDROID_ABI MATCHES "armeabi-v7a")'
  convert_cache booster-data/android-arm.txt
echo 'elseif (ANDROID_ABI MATCHES "x86_64")'
  convert_cache booster-data/android-x86_64.txt
echo 'elseif (ANDROID_ABI MATCHES "x86")'
  convert_cache booster-data/android-x86.txt
echo 'elseif (UNIX AND NOT APPLE)'
  convert_cache booster-data/linux-x86_64.txt
echo "endif ()"
) > booster.cmake
