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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.18@swift-5/AGDnsProxy-apple-2.2.18.zip",
      checksum: "cd20a9b921a4c5fad6d25719ca2856a3b121423af13c5ca1aadf9f8b5fc6a38f"
    ),
  ]
)

