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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.16@swift-5/AGDnsProxy-apple-2.5.16.zip",
      checksum: "dbb19f3b7e340f573a2612f8dbcded924e8ab5412fd4488ddb219234bb422276"
    ),
  ]
)

