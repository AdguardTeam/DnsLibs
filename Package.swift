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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.2@swift-5/AGDnsProxy-apple-2.0.2.zip",
      checksum: "d6502733afe4f00db1979918c5a5b20baea1551b35a650671a0bc289721396ab"
    ),
  ]
)

