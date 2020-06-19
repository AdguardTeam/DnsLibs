# AdGuard C++ DNS libraries

A DNS proxy library that supports all existing DNS protocols including `DNS-over-TLS`,
`DNS-over-HTTPS`, and `DNSCrypt`.

## After checkout

```
git submodule init
git submodule update
```
In order to reset submodules you can use 
```
git submodule update --force
``` 
## Build instructions

### Native library

#### Prerequisites

* CMake 3.6 or higher
* GCC 9 or higher / Clang 8 or higher

#### Building

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

* CMake 3.6 or higher
* Clang 8 or higher
* Xcode 11 or higher

#### Building

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

Copyright (C) AdGuard Software Ltd.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
