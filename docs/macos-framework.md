# macOS/iOS framework

This document describes how to build the `AGDnsProxy` framework for macOS and iOS.

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
cd <path/to/dnsproxy>
bash platform/mac/framework/build_dnsproxy_framework.sh \
    --bp <build_path> \
    --fwp <path/to/dnsproxy>/platform/mac/framework/
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

## Testing the framework

The framework project includes Objective-C++ unit tests, but they are only available for the `macos` target.
To build and run them, configure the framework CMake project for macOS and use the `tests` target:

```shell
cd <path/to/dnsproxy>/platform/mac/framework
mkdir build && cd build
cmake .. -DTARGET_OS=macos -DCMAKE_BUILD_TYPE=RelWithDebInfo -GNinja
ninja tests
ctest
```

For iOS or iPhone simulator targets the `tests` target is empty, so `ctest` will have nothing to run.
