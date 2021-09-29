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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.47@swift-5/AGDnsProxy-apple-1.6.47.zip",
      checksum: "2e1d2d3c71ce08c2d6f148b0f2b2d5de2f313711adf9d4e3321f9c45c5548882"
    ),
  ]
)

