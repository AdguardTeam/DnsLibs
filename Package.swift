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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.25@swift-5/AGDnsProxy-apple-1.6.25.zip",
      checksum: "533568bd729c1f841fb7828b689b9808bb481c5724e1c0f913929942fad1c246"
    ),
  ]
)

