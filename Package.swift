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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.20@swift-5/AGDnsProxy-apple-2.5.20.zip",
      checksum: "9cb14cf46bb5138d0e410694ea3f168b384ae750ee53eef024196f724df1ed44"
    ),
  ]
)

