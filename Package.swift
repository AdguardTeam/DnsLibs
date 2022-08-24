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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.0@swift-5/AGDnsProxy-apple-2.0.0.zip",
      checksum: "cec2b3a043132eedfdac80db0a7bd6c84b3dcef327452f1075fb8b057aae98c8"
    ),
  ]
)

