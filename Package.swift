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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.23@swift-5/AGDnsProxy-apple-2.2.23.zip",
      checksum: "cf93f8b37e732f7bae46dba1b147348a089ababaaf05369ac23d088559db0a6f"
    ),
  ]
)

