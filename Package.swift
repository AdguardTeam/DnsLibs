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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.25@swift-5/AGDnsProxy-apple-2.5.25.zip",
      checksum: "824614af9b1355406517208dd7eb402b88faffcef998a538ef399e6e5f79dd0d"
    ),
  ]
)

