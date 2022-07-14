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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.42@swift-5/AGDnsProxy-apple-1.7.42.zip",
      checksum: "b0a9e2ba053498cb06dec69244a4c3fb8879ddd37bca403dec8e7f3ea2a607f4"
    ),
  ]
)

