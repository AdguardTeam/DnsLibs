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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.5@swift-5/AGDnsProxy-apple-1.6.5.zip",
      checksum: "d6e42b862b326df25e69ed00a35857813d0491d22be14a3d53540864791c6689"
    ),
  ]
)

