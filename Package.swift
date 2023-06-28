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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.13@swift-5/AGDnsProxy-apple-2.2.13.zip",
      checksum: "1c078a64bed9a2cdff9fc522fc30e2413baeafb580c1bc73b85d4bf7fc3a421e"
    ),
  ]
)

