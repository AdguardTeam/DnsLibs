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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.71@swift-5/AGDnsProxy-apple-1.6.71.zip",
      checksum: "6e2c25a37e23e45fae0198d3ccec93f5c5157c7e5da730d979e8f42abae7d1a9"
    ),
  ]
)

