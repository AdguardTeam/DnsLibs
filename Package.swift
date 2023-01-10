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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.71@swift-5/AGDnsProxy-apple-2.0.71.zip",
      checksum: "d8ce3f0faa894c055db1f48ea1f108ec6d7cb75a1d5cf9ad01502cbc75447441"
    ),
  ]
)

