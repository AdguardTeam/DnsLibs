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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.12@swift-5/AGDnsProxy-apple-2.0.12.zip",
      checksum: "ffad5143265942cdd6330d978d920265c5e4deebc441d246e9a7e53b57b4a626"
    ),
  ]
)

