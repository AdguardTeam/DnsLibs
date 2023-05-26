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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.8@swift-5/AGDnsProxy-apple-2.2.8.zip",
      checksum: "8c66eb5bdd90a927dd8644d7d893d5e2258b21c435b6cf40f6a835091816d6eb"
    ),
  ]
)

