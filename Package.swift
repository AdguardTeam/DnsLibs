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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.46@swift-5/AGDnsProxy-apple-2.5.46.zip",
      checksum: "d9e4595b24b1a996d3564e28cb8b1a19653b7d4605155df6f5707fcf5155384d"
    ),
  ]
)

