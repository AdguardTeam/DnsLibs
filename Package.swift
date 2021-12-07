// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "AGDnsProxy",
  platforms: [
    .iOS("10.0"), .macOS("10.12")
  ],
  products: [
    .library(name: "AGDnsProxy", targets: ["AGDnsProxy"]),
  ],
  targets: [
    .binaryTarget(
      name: "AGDnsProxy",
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.70@swift-5/AGDnsProxy-apple-1.6.70.zip",
      checksum: "b38fedf848497e63759feb0cfa20d73a6f399f66570743a34af13951be373580"
    ),
  ]
)

