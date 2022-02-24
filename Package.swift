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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.11@swift-5/AGDnsProxy-apple-1.7.11.zip",
      checksum: "61b031a4b7f39818ff7547c5e325e142b651d1e95fc1487926a0d2a565a5fda2"
    ),
  ]
)

