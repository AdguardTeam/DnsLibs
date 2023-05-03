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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.1@swift-5/AGDnsProxy-apple-2.2.1.zip",
      checksum: "a43a5f6c627300a9ea870e2c68a7cdd25d4873003be09c5961c0dd1bcf843ceb"
    ),
  ]
)

