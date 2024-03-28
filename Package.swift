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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.14@swift-5/AGDnsProxy-apple-2.5.14.zip",
      checksum: "c87fb11212f30438a3a1c8f0c8aaee892948d4f7e42918163d5195e57ac02d36"
    ),
  ]
)

