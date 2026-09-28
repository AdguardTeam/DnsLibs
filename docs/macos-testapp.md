# macOS/iOS sample app

This document describes `platform/mac/DnsLibsTestApp`, the macOS and iOS sample app of this repository (Swift,
`NEDNSProxyProvider` / `NEPacketTunnelProvider`, macOS system extension).

The app uses the `AGDnsProxy` framework built from this repository. The framework is not referenced by the Xcode
project as a file: every target that needs it runs `platform/mac/framework/build_framework_for_xcode.sh` from a
"Build AGDnsProxy framework" build phase, links it with `-framework AGDnsProxy`, and embeds it from an
"Embed AGDnsProxy framework" build phase. See [macOS/iOS framework](macos-framework.md) for the framework itself.

The app is configured for automatic signing with the `TC3Q7MAJXF` team and requires access to it (or changing
`DEVELOPMENT_TEAM` to a team of your own) to build for a device.

## Prerequisites

Building an app builds the framework and its Conan dependencies, so the tools from the
[framework prerequisites](macos-framework.md#prerequisites) are needed: Conan 2.0.5 or higher, CMake 3.24 or higher,
Ninja, and Xcode.

Xcode build phases do not inherit the `PATH` of your shell, so a build started from the Xcode GUI does not see tools
installed by Homebrew, pipx, or a similar per-user install unless they are in a standard location. The framework build
phase looks in `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/Library/Python/*/bin`, and
`/Applications/CMake.app/Contents/bin`, and fails with a list of the tools it could not find. To use tools installed
elsewhere, set `DNSLIBS_TOOL_PATH` to their directory (or to a colon-separated list of directories) as a build setting:

- in the Xcode GUI — add a user-defined setting named `DNSLIBS_TOOL_PATH` to the build settings of the project;
- on the command line — pass it to `xcodebuild`:
  `xcodebuild DNSLIBS_TOOL_PATH=/opt/tools/bin ... build`.

`platform/mac/DnsLibsTestApp/DnsLibsTestApp.xcodeproj` contains four targets:

| Target | Product | Platform | Purpose |
| --- | --- | --- | --- |
| `DnsLibsTestApp` | app | macOS, iOS | UI: starts/stops the selected provider and shows DNS request events |
| `SystemExtension` | system extension | macOS | Hosts the packet tunnel and the DNS proxy on macOS |
| `PacketTunnel` | app extension | iOS | `NEPacketTunnelProvider` |
| `DnsProxy` | app extension | iOS | `NEDNSProxyProvider` |

## Build

### Xcode GUI

1. Open `platform/mac/DnsLibsTestApp/DnsLibsTestApp.xcodeproj`.
2. Select the `DnsLibsTestApp` scheme.
3. Select a destination: **My Mac** for macOS, or an iOS device or simulator.
4. Press `Command+B` to build, `Command+R` to run.

The shared schemes checked into the repository are `DnsLibsTestApp`, `DnsProxy`, and `PacketTunnel`; the latter two
build the app together with the corresponding extension and run the app. The `SystemExtension` target is built as a
dependency of the app on macOS; to build it alone, use the scheme Xcode autocreates for it (it is not shared) or
`xcodebuild -target SystemExtension`.

The first build takes a while: the "Build AGDnsProxy framework" phase builds the `AGDnsProxy` framework and, on a clean
Conan cache, its dependencies. Later builds only rebuild what changed, and switching between macOS and iOS builds the
framework slice of the new destination.

### Command line

```shell
cd <dns-libs-dir>/platform/mac/DnsLibsTestApp

# macOS
xcodebuild -scheme DnsLibsTestApp -destination 'platform=macOS' build

# iOS simulator
xcodebuild -scheme DnsLibsTestApp -destination 'platform=iOS Simulator,name=iPhone 17' build

# iOS device (requires signing access to the development team)
xcodebuild -scheme DnsLibsTestApp -destination 'generic/platform=iOS' build
```

Add `-configuration Release` for a release build and `-derivedDataPath <path>` to keep the build products out of the
default `DerivedData`.

> Build for a concrete destination (a Mac, a simulator, or a device). The framework is built for a single architecture,
> so the project sets `ONLY_ACTIVE_ARCH = YES`; a generic destination that asks for several architectures at once is
> rejected by the framework build phase.

## Use

1. Select the provider to test: **Packet Tunnel** or **DNS Proxy**.
2. Optionally change the upstream (the default is `https://dns.adguard-dns.com/dns-query`). Both plain and encrypted
   upstreams are supported, e.g. `tls://94.140.14.14` or `https://dns.adguard-dns.com/dns-query`.
3. Press **Start** and approve the VPN/DNS configuration when the system asks for it. **Stop** stops the provider,
   **Delete** removes its configuration from the system.

DNS request events are written by the extension into the app group container
(`group.com.adguard.dns.DnsLibsTestApp`) and shown by the app as `Request: <domain> <type>` lines.

### macOS

Because the app installs a system extension, it MUST be copied to the `/Applications` folder to work.

Allow extensions for the app in **System Settings** > **General** > **Login Items & Extensions** >
**DnsLibsTestApp**).

### iOS

The packet tunnel is a regular app extension and starts with a system prompt.

`NEDNSProxyProvider` cannot be enabled by an app on iOS: it needs a DNS proxy configuration profile installed through
MDM. A sample profile is included in `platform/mac/DnsLibsTestApp/mdm/DnsLibsTestApp-DnsProxy.mobileconfig`; see
[NEDnsProxyProvider support](dns-proxy-provider.md) for details.
