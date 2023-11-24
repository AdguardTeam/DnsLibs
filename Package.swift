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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.16@swift-5/AGDnsProxy-apple-2.4.16.zip",
      checksum: "dbd7c63a4d2a39e9f44ae5938ec3716b7e7a8b7481eff046e51ab693830fb237"
    ),
  ]
)

