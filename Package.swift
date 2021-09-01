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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.32@swift-5/AGDnsProxy-apple-1.6.32.zip",
      checksum: "df5c4065ab82d72b4bc46b256e0f7506a82fa694449d8e50189f066f88719a98"
    ),
  ]
)

