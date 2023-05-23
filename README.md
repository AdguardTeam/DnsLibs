# AdGuard C++ DNS libraries

A DNS proxy library that supports all existing DNS protocols including `DNS-over-TLS`,
`DNS-over-HTTPS`, `DNSCrypt` and `DNS-over-QUIC`.

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

* Proxy configuration: [native](proxy/include/proxy/DnsProxySettings.h), [mac](platform/mac/framework/AGDnsProxy.h),
[android](platform/android/dnsproxy/lib/src/main/java/com/adguard/dnslibs/proxy/DnsProxySettings.java)
* [Rules syntax](https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists)
* [Developer documentation](documentation/DEV_DOCS.en.md)

## Testing changes as a dependency

To test local changes in the library in case it is used as a conan package dependency,
do the following:

1) Create patch files: e.g., execute `git diff > 1.patch` in the project root.
2) Add paths to the patch files in `<root>/conanfile.py`, see the `patch_files` field.
3) Change the `vcs_url` field in `<root>/conanfile.py` if the default one is not suitable.
4) Export the conan package with the special version number: `conan export . /777@AdguardTeam/NativeLibsCommon`.
5) In the project that uses `dns-libs` as a dependency, change the version to `777`
   (e.g. `dns-libs/1.0.0@AdguardTeam/NativeLibsCommon` -> `dns-libs/777@AdguardTeam/NativeLibsCommon`).
6) Re-run cmake command.  
   Notes:
    * if one has already exported the library in such way, the cached version must be purged: `conan remove -f dns-libs/777`,
    * by default the patches are applied to the `master` branch, specify the `commit_hash` option to test changes against the specific commit.

## License

Apache 2.0
