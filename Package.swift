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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.12@swift-5/AGDnsProxy-apple-1.7.12.zip",
      checksum: "687b4158db60d104e179719f0ce0b0ba7d8d4454e48d87c24bf3f4b46dd47d67"
    ),
  ]
)

