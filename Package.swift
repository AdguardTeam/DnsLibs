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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.45@swift-5/AGDnsProxy-apple-2.5.45.zip",
      checksum: "a171b918d79b79840517b8d56430fc0a0687417704b9a8b29ebc058da2f15925"
    ),
  ]
)

