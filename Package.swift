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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.6.8@swift-5/AGDnsProxy-apple-2.6.8.zip",
      checksum: "2acacb8a030b8617eca72243380cb4ec11677572b760f21084ad7752631caf6d"
    ),
  ]
)

