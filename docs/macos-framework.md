# macOS/iOS framework

This document describes how to build the `AGDnsProxy` framework for macOS and iOS.

## Minimum OS versions

The framework is built with these deployment targets (set in `platform/mac/framework/CMakeLists.txt` and declared in
`platform/mac/packaging/AGDnsProxy.podspec.json` and `platform/mac/packaging/Package.swift`):

| Platform | Minimum version |
| --- | --- |
| macOS | 12.0 |
| iOS / iPhone simulator | 15.0 |

## Prerequisites

- Conan C++ package manager 2.0.5 or higher
- CMake 3.24 or higher
- Clang/LLVM 21 or higher
- Xcode with a compatible Clang version

## Building

If this is a clean build, first export the custom Conan packages to the local Conan cache.
See the [NativeLibsCommon README](https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md) for details.

Run the helper script from the repository root. The `--bp` and `--fwp` options are effectively required for
command-line builds because the script defaults rely on Xcode's `SRCROOT`:

```shell
cd <dns-libs-dir>
bash platform/mac/framework/build_dnsproxy_framework.sh \
    --bp <build_path> \
    --fwp <dns-libs-dir>/platform/mac/framework/
```

For a full list of options run:

```shell
bash platform/mac/framework/build_dnsproxy_framework.sh --help
```

### Supported `--os` values

- `macos-x86_64`
- `macos-arm64`
- `ios`
- `iphonesimulator-x86_64`
- `iphonesimulator-arm64`
- `all` (default)

The default is `all`, which builds all five variants and produces a multi-platform `.xcframework`.

### Script options

- `--os <value>` — target platform (default `all`).
- `--tn <name>` — framework name (default `AGDnsProxy`).
- `--bp <path>` — build directory path.
- `--fwp <path>` — framework CMake project path.
- `--debug` — force a `Debug` build.
- `clean` — remove the build directory.

### Output

The script assembles the output in `<build_path>`:

- `<build_path>/<target_name>.framework` — when a single platform is requested.
- `<build_path>/<target_name>.xcframework` — when multiple platforms are requested (the default).
- `<build_path>/<target_name>.dSYMs` — debug symbols for the multi-platform build.

`<target_name>` is the framework name (`AGDnsProxy` by default).

## Building a single slice for Xcode

`platform/mac/framework/build_framework_for_xcode.sh` is a thin wrapper around `build_dnsproxy_framework.sh` that
builds exactly one slice — the platform and architecture Xcode is currently targeting — and publishes it at
`<output_dir>/build/<PLATFORM_NAME>/AGDnsProxy.framework`, which is where the sample Xcode project looks for it. It is
what the "Build AGDnsProxy framework" build phase of the [sample app](macos-testapp.md) runs, and it takes its
defaults from the Xcode environment (`PLATFORM_NAME`, `ARCHS`, `PROJECT_DIR`, `ACTION`).

Each slice gets its own CMake build directory, so switching destinations in Xcode does not invalidate the cache of the
other slices and repeated builds stay incremental. Concurrent invocations (several targets building the same slice in
parallel) are serialized with a lock.

To run it by hand:

```shell
bash platform/mac/framework/build_framework_for_xcode.sh \
    --platform macosx \
    --arch arm64 \
    --bp <output_dir>
```

- `--platform <name>` — `macosx`, `iphoneos`, or `iphonesimulator`; defaults to `${PLATFORM_NAME}`.
- `--arch <name>` — a single architecture; defaults to `${ARCHS}` or to the host architecture. The framework cannot be
  built for several architectures at once, so the sample project sets `ONLY_ACTIVE_ARCH = YES`.
- `--bp <path>` — output directory; defaults to `${PROJECT_DIR}/framework`.
- `--debug` — build `Debug` instead of the default `RelWithDebInfo`. This also needs `Debug` builds of the Conan
  dependencies, which the other workflows do not put into the local Conan cache.
- `--help` — show the usage message.

Xcode build phases do not inherit the `PATH` of an interactive shell, so the script also looks for `cmake`, `ninja`,
and `conan` in `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/Library/Python/*/bin`, and
`/Applications/CMake.app/Contents/bin`. Set the `DNSLIBS_TOOL_PATH` build setting to a colon-separated list of
directories to add more.

## Testing the framework

The framework project includes Objective-C++ unit tests, but they are only available for the `macos` target.
To build and run them, configure the framework CMake project for macOS and use the `tests` target:

```shell
cd <dns-libs-dir>/platform/mac/framework
mkdir build && cd build
cmake .. -DTARGET_OS=macos -DCMAKE_BUILD_TYPE=RelWithDebInfo -GNinja
ninja tests
ctest
```

For iOS or iPhone simulator targets the `tests` target is empty, so `ctest` will have nothing to run.
