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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.50@swift-5/AGDnsProxy-apple-1.6.50.zip",
      checksum: "133e30088108ca455b2524a4be2e8ecdfbaee4a307ee37e072d884a09fff246e"
    ),
  ]
)

