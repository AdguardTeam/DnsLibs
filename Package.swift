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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.9@swift-5/AGDnsProxy-apple-1.6.9.zip",
      checksum: "47959c8e959876e472a510dcc7d96a1ef5223a432eb94a36d38541f15634d3af"
    ),
  ]
)

