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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.40@swift-5/AGDnsProxy-apple-1.5.40.zip",
      checksum: "97b06d45f6924967caecec7b8b562b41a19c088c0bb617da22561237f362d42c"
    ),
  ]
)

