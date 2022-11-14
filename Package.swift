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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.56@swift-5/AGDnsProxy-apple-2.0.56.zip",
      checksum: "a94746f72de29169ae8dc80d55406b385354840d1f6fffc24d41b29fb17e1c88"
    ),
  ]
)

