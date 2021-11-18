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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.66@swift-5/AGDnsProxy-apple-1.6.66.zip",
      checksum: "6a77925304acc1ee4beeedd3cd3a6aec50bd5bdca2c36223aedd257f0088f26c"
    ),
  ]
)

