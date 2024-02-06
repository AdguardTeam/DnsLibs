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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.50@swift-5/AGDnsProxy-apple-2.4.50.zip",
      checksum: "4f2a744638d24d7d6b9f51190ad0552b42da9653cea4a69b72e8c554b6c0753b"
    ),
  ]
)

