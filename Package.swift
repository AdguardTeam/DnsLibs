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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.22@swift-5/AGDnsProxy-apple-1.7.22.zip",
      checksum: "5e7860bd9c349090e3cd37f20bce1b2a67382fe0f2648b27d7ab7124bd845970"
    ),
  ]
)

