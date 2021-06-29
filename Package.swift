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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.4@swift-5/AGDnsProxy-apple-1.6.4.zip",
      checksum: "3f1eff5392b5d4c7f6f406d57845a2f8f7c05b9d5b397003ae1e89dcae6bb4af"
    ),
  ]
)

