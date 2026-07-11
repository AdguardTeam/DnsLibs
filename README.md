# AdGuard C++ DNS libraries

A DNS proxy library that supports all existing DNS protocols including `DNS-over-TLS`,
`DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`.

## Supported platforms

- Linux
- macOS
- iOS
- Windows
- Android

## Features

- Caching, filtering, encryption, and redirection of DNS requests.
- Support for all modern encrypted DNS protocols:
    - DNS-over-TLS (DoT)
    - DNS-over-HTTPS (DoH)
    - DNS-over-QUIC (DoQ)
    - DNSCrypt
- Cross-platform C++ core with platform-specific adapters for macOS, iOS, Android, and Windows.

## Usage

The library is organized into a shared C++ core and platform-specific adapters.

- Proxy configuration:
    - [native](proxy/include/dns/proxy/dnsproxy_settings.h)
    - [macOS/iOS](platform/mac/framework/AGDnsProxy.h)
    - [Android](platform/android/dnsproxy/lib/src/main/java/com/adguard/dnslibs/proxy/DnsProxySettings.java)
- [Filtering rules syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)

## Documentation

- [Developer documentation](DEVELOPMENT.md) — how to build, test, and develop the library.
- Platform-specific build and integration guides:
    - [macOS/iOS framework](docs/macos-framework.md)
    - [macOS DNS proxy sample app](docs/macos-testapp.md)
    - [Android platform adapter](docs/android.md)
    - [Windows C API DLL](docs/windows-capi.md)
    - [Windows C# test application](docs/windows-testapp.md)
    - [NEDnsProxyProvider support](docs/dns-proxy-provider.md)
- [Project conventions](AGENTS.md)

## License

Apache 2.0
