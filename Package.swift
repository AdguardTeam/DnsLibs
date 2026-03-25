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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.8.45@swift-5/AGDnsProxy-apple-2.8.45.zip",
      checksum: "f9d0495427909b19376bfe6fead93af6c9acc401880fddf29de3dd89244c552b"
    ),
  ]
)

