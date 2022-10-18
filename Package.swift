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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.30@swift-5/AGDnsProxy-apple-2.0.30.zip",
      checksum: "3b749be7e6eb7d3367d5a465da110e726e589aa56a956ccf4522d64579c21a58"
    ),
  ]
)

