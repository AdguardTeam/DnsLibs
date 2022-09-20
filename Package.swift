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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.16@swift-5/AGDnsProxy-apple-2.0.16.zip",
      checksum: "1a3968ede4ea19aba5453804ae4eb5f34667bcc155ec975247bc7284c3c7f700"
    ),
  ]
)

