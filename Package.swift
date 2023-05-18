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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.5@swift-5/AGDnsProxy-apple-2.2.5.zip",
      checksum: "0856ce9ef57638f666003d52c424f7037a96d5086a504929d9edf34570c4c7b0"
    ),
  ]
)

