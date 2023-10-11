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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.3.5@swift-5/AGDnsProxy-apple-2.3.5.zip",
      checksum: "4b8cf8c5d2483d31b2b5ae150ca6872dd935a951d76e8e54d87ae60ba2861779"
    ),
  ]
)

