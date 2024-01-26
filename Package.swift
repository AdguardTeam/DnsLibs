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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.47@swift-5/AGDnsProxy-apple-2.4.47.zip",
      checksum: "911c6e3cd4de11da1f4eccb4602f4e9f0aca828a6f17dd4687777971f33d03b1"
    ),
  ]
)

