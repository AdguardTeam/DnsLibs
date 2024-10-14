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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.49@swift-5/AGDnsProxy-apple-2.5.49.zip",
      checksum: "ea8a5f7aac5e0069e27bd03e5e4429de3e0fb6d1d45b2e57105252449afcd7c8"
    ),
  ]
)

