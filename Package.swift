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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.27@swift-5/AGDnsProxy-apple-1.6.27.zip",
      checksum: "719c2c6a87c25c91ec6cd4ab0c2e3b6b450d99dd021e5d3a30a336e631aa38f0"
    ),
  ]
)

