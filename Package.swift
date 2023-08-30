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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.24@swift-5/AGDnsProxy-apple-2.2.24.zip",
      checksum: "4a4785e15f52f95df5f5a22a0f6e442e0bc98e15212efbc8915dc5089e5010fd"
    ),
  ]
)

