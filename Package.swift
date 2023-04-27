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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.1.38@swift-5/AGDnsProxy-apple-2.1.38.zip",
      checksum: "1ea4afbaeaecb5581040122a4b9c689c3ce9ce70e4f80335f6fc67c142a3ed34"
    ),
  ]
)

