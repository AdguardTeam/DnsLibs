# Android platform adapter

This document describes how to build the Android library and the standalone TUN-based test app.

## Prerequisites

- Android Studio or the Android command-line tools
- JDK 17 or higher (required by Android Gradle Plugin 8.4.0)
- Android SDK with API 34 installed
- Android NDK 29.0.14206865 (the version is pinned in `build.gradle`)
- CMake 3.24 or higher
- Conan 2.0.5 or higher
- Python 3.7 or higher
- Internet access for the first build (CMake bootstraps Conan and downloads native dependencies)

## Project structure

- `platform/android/dnsproxy/lib` — the `dns-libs` Android library (AAR).
- `platform/android/dnsproxy/dnstun-app` — a standalone TUN-based sample application.

## Configure the project

Create `platform/android/dnsproxy/local.properties` with the paths to your Android SDK and NDK:

```properties
sdk.dir=/path/to/android-sdk
ndk.dir=/path/to/android-ndk/29.0.14206865
cmake.dir=path to directory containing "bin/cmake" e.g. /opt/homebrew or /usr/bin
```

The root build script also optionally applies `additional.gradle` and `buildscript.additional.gradle` for extra internal configuration.

## Building the library

The native `adguard-dns` shared library is built automatically by Gradle through CMake, always using `RelWithDebInfo` and `c++_static` STL. Conan dependencies are resolved automatically by CMake; ensure `conan` is on `PATH` and can access the network for the first build.

To build the AAR:

```shell
cd <dns-libs-dir>/platform/android/dnsproxy
./gradlew :lib:assembleRelease
```

The AAR is produced in `platform/android/dnsproxy/lib/build/outputs/aar/`.

## Running tests

JVM unit tests:

```shell
./gradlew :lib:test
```

Instrumented tests (requires a connected device or emulator):

```shell
./gradlew :lib:connectedAndroidTest
```

## Building the test app

```shell
cd <dns-libs-dir>/platform/android/dnsproxy
./gradlew :dnstun-app:assembleDebug
```

Install and run the app on a connected device:

```shell
./gradlew :dnstun-app:installDebug
```

## Publishing

The library is configured to publish as `com.adguard.corelibs:dns-libs`. The version is resolved from the `dnsLibsVersion` project property, the `DNS_LIBS_VERSION` environment variable, or the latest Git tag matching `v*`. To publish to the local Maven repository:

```shell
./gradlew :lib:publishToMavenLocal
```

> `jcenter()` is still declared in the root build script as a read-only repository, but it is deprecated and may be removed in the future.
