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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.22@swift-5/AGDnsProxy-apple-1.6.22.zip",
      checksum: "2dd53056d0f94865b21a530dd9b5d52466321f75746f8a8256f5c2e1684fdb5f"
    ),
  ]
)

