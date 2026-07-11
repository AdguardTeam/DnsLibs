# macOS DNS proxy sample application

This document describes how to build and run the macOS/iOS sample application located in
`platform/mac/testapp`.

## Build

### Xcode GUI

1. Open `platform/mac/testapp/test.xcodeproj` in Xcode.
2. Select the desired target or scheme (`test-ios` or `test-macos`).
3. Press `Command+B` to build.

> Only the `test-ios` and `ext-ios` schemes are checked into the repository. If you want to build `test-macos`
> from the terminal, use the `test-macos` target instead of a scheme.

### Terminal

For the iOS target:

```shell
cd <dns-libs-dir>/platform/mac/testapp
xcodebuild -project test.xcodeproj -scheme test-ios
```

For the macOS target:

```shell
cd <dns-libs-dir>/platform/mac/testapp
xcodebuild -project test.xcodeproj -target test-macos
```

## Run

### macOS

The macOS app starts the VPN service automatically when it launches (`AGVpnStart()` in `test-macos/AppDelegate.m`).
The first time you run it, macOS asks you to approve the new VPN configuration. After that, the service is created
and started automatically.

The service name shown in **System Settings > Network** is `DnsLibs Sample` (set in `common/vpn.m`).

### iOS

#### Xcode GUI

1. Select the `test-ios` scheme.
2. Press `Command+R`.

### Set the DNS proxy as the system DNS server (optional)

The macOS and iOS test apps both configure `NEDNSSettings` programmatically in `PacketTunnelProvider.m`, with DNS
server `198.18.0.1` (and `2001:ad00:ad00::ad00` for IPv6). On modern systems this is usually sufficient; if the
DNS is not being routed through the tunnel, you can also configure it manually:

1. Open **System Settings** > **Network**.
2. Select the connection you want to filter.
3. Go to **Details** > **DNS**.
4. Add the DNS server address: `198.18.0.1` (hardcoded as the DNS server in `PacketTunnelProvider.m`).

> The tunnel interface address is `172.16.209.2` (IPv4) and `fd12:1:1:1::2` (IPv6), while `127.1.1.1` is used as the
> tunnel remote address.
