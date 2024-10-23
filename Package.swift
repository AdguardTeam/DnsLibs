// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "AGDnsProxy",
  platforms: [
    .iOS("11.2"), .macOS("10.13")
  ],
  products: [
    .library(name: "AGDnsProxy", targets: ["AGDnsProxy"]),
  ],
  targets: [
    .binaryTarget(
      name: "AGDnsProxy",
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.51@swift-5/AGDnsProxy-apple-2.5.51.zip",
      checksum: "e6434e970021f47b6307b15ae5bea65ed5f91ef526c36cc1d947da5555d99c94"
    ),
  ]
)

