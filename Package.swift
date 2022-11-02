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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.38@swift-5/AGDnsProxy-apple-2.0.38.zip",
      checksum: "413507c8117b037e7536c3305fd5785f60e874a51804a5fa1b2dcb36457509d0"
    ),
  ]
)

