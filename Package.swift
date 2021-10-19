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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.58@swift-5/AGDnsProxy-apple-1.6.58.zip",
      checksum: "73d71f5aafc38b307d83f4e3fe90441c87b35716bba611b30d39586b8ef8f0c3"
    ),
  ]
)

