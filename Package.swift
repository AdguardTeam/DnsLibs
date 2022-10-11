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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.27@swift-5/AGDnsProxy-apple-2.0.27.zip",
      checksum: "f45df69d5d5ea42eea1ff7bd556ca795f71fc2c9a2d622eb716198a74d7c434f"
    ),
  ]
)

