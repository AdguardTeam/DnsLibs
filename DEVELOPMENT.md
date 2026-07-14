# Developer documentation


This document is intended for developers who build, modify, or debug the AdGuard DNS libraries.

For coding style, project structure, and logging conventions see [AGENTS.md](AGENTS.md).

## Table of contents

- [Getting started](#getting-started)
- [Build the native library](#build-the-native-library)
- [Platform-specific builds](#platform-specific-builds)
- [Architecture overview](#architecture-overview)
- [Testing changes as a dependency](#testing-changes-as-a-dependency)
- [Useful notes](#useful-notes)

## Getting started

Set up the development environment after cloning the repository:

```shell
make init
```

This configures the git hooks path to `./scripts/hooks`.

## Build the native library

### Prerequisites

- Conan C++ package manager 2.0.5 or higher
- Python 3.8 or higher (for dependency bootstrapping via `scripts/bootstrap_conan_deps.py`
  and the `clangd-tidy` linter, both run through a venv created from `requirements.txt`)
- CMake 3.24 or higher
- Clang/LLVM 21 or higher (GCC 9 or higher is also supported for native builds)
- Ninja
- Node.js/npm (for Markdown linting via `markdownlint-cli2`, which is fetched automatically with `npx -y`)

If this is a clean build, export the custom Conan packages to the local Conan cache. See the
[NativeLibsCommon README](https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md) for details.

### Building

The repository provides a Makefile with the most common targets. To build the native `dnsproxy` library:

```shell
make build_libs
```

For a debug build:

```shell
BUILD_TYPE=debug make build_libs
```

This bootstraps Conan dependencies, configures CMake, and builds the `dnsproxy` target.

### Testing

To build and run the C++ unit tests:

```shell
make test
```

This is equivalent to `make test-cpp`, which builds the `tests` target and runs `ctest`.

### Linting

The following `make` targets are available for linting:

- `make lint` runs all linters (`lint-md` and `lint-cpp`).
- `make lint-fix` auto-fixes fixable issues for both Markdown and C++.
- `make lint-md` lints Markdown files with `markdownlint-cli2` (configured via `.markdownlint-cli2.yaml`).
- `make lint-fix-md` auto-fixes Markdown files.
- `make lint-cpp` checks C++ formatting with `clang-format` and runs `clangd-tidy`.
- `make lint-fix-cpp` auto-fixes C++ formatting with `clang-format`.

### Manual CMake build

You can also build directly with CMake:

```shell
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -G Ninja
cmake --build . --target tests -j 4
ctest -j 4
```

The `listener_standalone` target is a small standalone proxy that can be used for quick experiments:

```shell
cmake --build . --target listener_standalone -j 4
```

By default, `listener_standalone` listens on UDP port 1234 and TCP port 1234 and forwards all DNS
requests to `8.8.8.8:53` or `8.8.4.4:53`. You can change the port, timeout, and other settings in
`proxy/test/listener_standalone.cpp`.

## Platform-specific builds

Platform-specific build instructions are kept in the `docs` folder:

- [macOS/iOS framework](docs/macos-framework.md)
- [macOS DNS proxy sample app](docs/macos-testapp.md)
- [Android platform adapter](docs/android.md)
- [Windows C API DLL](docs/windows-capi.md)
- [Windows C# test application](docs/windows-testapp.md)
- [NEDnsProxyProvider support](docs/dns-proxy-provider.md)

## Architecture overview

For the architecture overview, main classes, and filtering rules see [docs/architecture.md](docs/architecture.md).

## Testing changes as a dependency

To test local changes in the library when it is used as a Conan package dependency, do the following:

1. If the default `vcs_url` in `conanfile.py` is not suitable, change it accordingly.
2. Commit the changes you wish to test. The exported version is derived from `git describe`,
   so the changes must be committed first.
3. Run `./scripts/export_conan.sh` to export the package to the local Conan cache. The version
   is taken from `git describe` (for example, `2.8.58` on a release tag, or `2.8.58-5-g<rev>`
   between tags), and the package is exported as `dns-libs/<version>@adguard/oss`.
4. In the project that depends on `dns-libs`, update the dependency reference to the exported
   version. Replace `dns-libs/1.0.0@adguard/oss` with `dns-libs/<version>@adguard/oss`, where
   `<version>` is the `git describe` output from step 3.
5. Re-run the CMake command.
   - If you have already exported the library, the cached version must be purged before
     re-exporting: `conan remove -f dns-libs/<version>@adguard/oss`.

To test uncommitted working-tree changes instead, export a special `local` version with
`conan create . --version local` and reference it as `dns-libs/local@adguard/oss`.

## Useful notes

- RFCs of DNS [1034](https://tools.ietf.org/html/rfc1034), [1035](https://tools.ietf.org/html/rfc1035);
- RFC of DNS-over-TLS [7858](https://tools.ietf.org/html/rfc7858);
- RFC of DNS-over-HTTPS [8484](https://tools.ietf.org/html/rfc8484);
- RFC(draft) of DNS-over-QUIC [draft-ietf-dprive-dnsoquic](https://datatracker.ietf.org/doc/draft-ietf-dprive-dnsoquic);
- [DNSCrypt](https://dnscrypt.info/stamps-specifications/) specifications;
- An Introduction to [libuv](https://nikhilm.github.io/uvbook/An%20Introduction%20to%20libuv.pdf);
- [LDNS](https://www.nlnetlabs.nl/documentation/ldns/) docs;
- [Filtering rules syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/).
