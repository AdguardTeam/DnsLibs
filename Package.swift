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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.36@swift-5/AGDnsProxy-apple-2.4.36.zip",
      checksum: "436084e09d561a99e094d29ae81ec874f0646e8cfc330cc1f1087f277a5df69e"
    ),
  ]
)

