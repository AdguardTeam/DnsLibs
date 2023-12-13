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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.29@swift-5/AGDnsProxy-apple-2.4.29.zip",
      checksum: "19f5c0881d5f7dbea6cdd54ae49c748e8a8caf132183fccfd143638789eea317"
    ),
  ]
)

