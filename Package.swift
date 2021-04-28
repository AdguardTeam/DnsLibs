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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.20@swift-5/AGDnsProxy-apple-1.5.20.zip",
      checksum: "be7e84f555d066cba0f6b72c50e7b0b7e4ed9841125675ee8545d4d0a01f74df"
    ),
  ]
)

