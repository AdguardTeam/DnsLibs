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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.8.44@swift-5/AGDnsProxy-apple-2.8.44.zip",
      checksum: "e993069eed3ed8e1f1582fddb235ad2e7e405f03c8715316d3833ba9aac7ff2d"
    ),
  ]
)

