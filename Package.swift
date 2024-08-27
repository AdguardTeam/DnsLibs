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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.41@swift-5/AGDnsProxy-apple-2.5.41.zip",
      checksum: "b47ace384d6e781c036465eaa7df0bdb6b4babbbbab7ee4b50730c07ceb383c2"
    ),
  ]
)

