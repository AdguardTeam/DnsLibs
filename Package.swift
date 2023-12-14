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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.32@swift-5/AGDnsProxy-apple-2.4.32.zip",
      checksum: "56aa5848ef72a75ba1ae490c14f0a4440e5ae1c19ab37c0d83cf5b7613226254"
    ),
  ]
)

