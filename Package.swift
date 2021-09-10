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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.36@swift-5/AGDnsProxy-apple-1.6.36.zip",
      checksum: "51e9955927448710335aa1b3205d149850dfb8083883e24936872e41ca9404c5"
    ),
  ]
)

