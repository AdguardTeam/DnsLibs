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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.34@swift-5/AGDnsProxy-apple-1.7.34.zip",
      checksum: "04eac5c3927c7ee0a05b301fec4c3493a45bc24a64d0d27643e0816de4cffdc0"
    ),
  ]
)

