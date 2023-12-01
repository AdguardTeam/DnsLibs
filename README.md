# AdGuard C++ DNS libraries

A DNS proxy library that supports all existing DNS protocols including `DNS-over-TLS`,
`DNS-over-HTTPS`, `DNSCrypt` and `DNS-over-QUIC`.

## Build instructions

### Native library

#### Prerequisites

* Conan C++ package manager 2.0.5 or higher
* CMake 3.24 or higher
* GCC 9 or higher / Clang 8 or higher

#### Building

If it is a clean build, export custom conan packages to the local conan repository.
See https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md for details.

Execute the following commands in Terminal:

* Windows

```shell
mkdir build && cd build
cmake -DCONAN_HOST_PROFILE="../conan/profiles/windows-msvc.jinja;auto-cmake" ..
```

* Other platforms

```shell
mkdir build && cd build
cmake ..               
```

For testing execute the following:
```
make -j 4 tests
ctest -j 4
```

### MacOS/iOS framework

#### Prerequisites

* Conan C++ package manager 2.0.5 or higher
* CMake 3.24 or higher
* Clang 8 or higher
* Xcode 11 or higher

#### Building

If it is a clean build, export custom conan packages to the local conan repository.
See https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md for details.

Execute the following commands in Terminal:
```
cd <path/to/dnsproxy>
bash platform/mac/framework/build_dnsproxy_framework.sh --bp <build_path> --fwp <path/to/dnsproxy>/platform/mac/framework/
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
To test local changes in the library when it is used as a Conan package dependency,
do the following:

1) If the default `vcs_url` in `<root>/conanfile.py` is not suitable, change it accordingly.
2) Commit the changes you wish to test.
3) Execute `./script/export_conan.py local`. This script will export the package, assigning the last commit hash as its version.
4) In the project that depends on `dns-libs`, update the version to `<commit_hash>` (where `<commit_hash>` is the hash of the target commit):
   Replace `dns-libs/1.0.0@adguard_team/native_libs_common` with `dns-libs/<commit_hash>@adguard_team/native_libs_common`.
5) Re-run the cmake command.
   Note:
   * If you have already exported the library in this way, the cached version must be purged: `conan remove -f dns-libs/<commit_hash>`.

## License

Apache 2.0
