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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.3@swift-5/AGDnsProxy-apple-1.7.3.zip",
      checksum: "086d9a89f215c883d7b7918d5072bc303de5c05137c324add6de608967b61fa0"
    ),
  ]
)

