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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.20@swift-5/AGDnsProxy-apple-1.6.20.zip",
      checksum: "d3b5543e4a9f009ac34773354c3eb663c8f5a2dfb1012499818329cdac79b987"
    ),
  ]
)

