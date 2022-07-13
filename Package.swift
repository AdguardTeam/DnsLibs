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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.41@swift-5/AGDnsProxy-apple-1.7.41.zip",
      checksum: "5d16e2d171ac47699c96974cc2c78185e4b87cd6790ec00499eb66ee1d61693f"
    ),
  ]
)

