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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.68@swift-5/AGDnsProxy-apple-2.0.68.zip",
      checksum: "9415be99ffc3d0831d8cafa6d489565ac3b26e2c422a9222df9d9832e52afabd"
    ),
  ]
)

