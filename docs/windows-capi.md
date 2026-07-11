# Windows C API

This document describes how to build the `AdguardDns`/`AdguardDns64`/`AdguardDnsArm64` DLL on Windows.

## Prerequisites

- Conan C++ package manager 2.0.5 or higher
- CMake 3.24 or higher
- Python 3
- Visual Studio 2022 17.6.1 or newer (MSVC 19.36 or newer)
- Ninja

See the main [DEVELOPMENT.md](../DEVELOPMENT.md) for how to use Conan in this repository.

## Build the DLL (x86 or x64)

Open the Visual Studio **Developer Command Prompt** and run:

```batch
if exist cmake-build-win rmdir /s /q cmake-build-win
mkdir cmake-build-win
cd cmake-build-win

:: On an x64 host, use vcvarsamd64_x86 for a 32-bit library.
:: For a native x86 host use vcvars32.
vcvarsamd64_x86

:: or for a 64-bit library:
vcvars64

cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ..

:: For a 32-bit library:
ninja AdguardDns

:: For a 64-bit library:
ninja AdguardDns64
```

## Build the DLL (64-bit ARM)

```batch
if exist cmake-build-win rmdir /s /q cmake-build-win
mkdir cmake-build-win
cd cmake-build-win
vcvarsall amd64_arm64

cmake -DCMAKE_BUILD_TYPE=Release -G Ninja -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_SYSTEM_PROCESSOR=ARM64 ..
ninja AdguardDnsArm64
```

## Build the helper executable

The `adguard-win-dns-helper` target builds the helper program:

```batch
ninja adguard-win-dns-helper
```

## Run tests

Build the DLL and run the following commands in the same prompt:

```batch
ninja tests
ctest
```

> `ctest` includes a committed-API-hash check (`git diff --quiet src/ag_dns_h_hash.inc`) that fails if the generated
> hash file has uncommitted changes. The C API tests also perform live DNS queries and require outbound network access.

## Output location

The CMake build copies the DLL and PDB to:

```text
platform/windows/cs/Adguard.Dns/Adguard.Dns/<arch>/
```

where `<arch>` is `x86`, `x64`, or `Arm64`.

## Windows helper sample

`src/win_dns_helper.cpp` contains an example of an elevated helper program that forces Windows to use the specified
plain DNS server addresses (loopback addresses may be specified) and prevents DNS queries to any other plain DNS
servers. It can also restore the original DNS settings when the process exits. Use it in scripts or launch it
alongside the DNS proxy. While the helper is running, DNS is restricted to the supplied servers; when the process exits,
it restores the original settings.
