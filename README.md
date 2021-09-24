# AdGuard C++ DNS libraries

A DNS proxy library that supports all existing DNS protocols including `DNS-over-TLS`,
`DNS-over-HTTPS`, `DNSCrypt` and `DNS-over-QUIC` (experimental).

## Build instructions

### Native library

#### Prerequisites

* Conan C++ package manager 1.38 or higher
* CMake 3.6 or higher
* GCC 9 or higher / Clang 8 or higher

#### Building

If it is a clean build, export custom conan packages to the local conan repository.
See https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md for details.

Execute the following commands in Terminal:
```
cd <path/to/dnsproxy>
mkdir build && cd build
cmake ..
make -j 4 dnsproxy
```

For testing execute the following:
```
make -j 4 tests
ctest -j 4
```

### MacOS/iOS framework

#### Prerequisites

* Conan C++ package manager 1.38 or higher
* CMake 3.6 or higher
* Clang 8 or higher
* Xcode 11 or higher

#### Building

If it is a clean build, export custom conan packages to the local conan repository.
See https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md for details.

Execute the following commands in Terminal:
```
cd <path/to/dnsproxy>
bash platform/mac/framework/build_dnsproxy_framework.sh --bp <build_path> --fwp <path/to/dnsproxy>/platform/mac/framework/ --iosv 13.0
```

For details of the building script usage execute the following:
```
bash platform/mac/framework/build_dnsproxy_framework.sh --help
```

As a result the DNS proxy framework will be located in `<build_path>/<target_name>.<framework_type>`,
where `<build_path>` is the build path one passed to script, `<target_name>` is the framework name,
`<framework_type>` is either `framework` (if one specified the target platform) or
`xcframework` (if one didn't specify any platform, or passed `all`).

## Useful notes

* Proxy configuration: [native](proxy/include/dnsproxy_settings.h), [mac](platform/mac/framework/AGDnsProxy.h),
[android](platform/android/dnsproxy/lib/src/main/java/com/adguard/dnslibs/proxy/DnsProxySettings.java)
* [Rules syntax](https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists)
* [Developer documentation](documentation/DEV_DOCS.en.md)

## License

Apache 2.0
