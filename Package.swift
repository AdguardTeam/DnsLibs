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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.11@swift-5/AGDnsProxy-apple-1.6.11.zip",
      checksum: "07947dc51d60a4879d71cff7946d6d9a5823f077da1d679cac1d0addf153db7e"
    ),
  ]
)

