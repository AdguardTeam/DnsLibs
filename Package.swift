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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.1.3@swift-5/AGDnsProxy-apple-2.1.3.zip",
      checksum: "101341a1eb350603a44ec174b90ede448a3554703866a1ee33514ea4112b59d4"
    ),
  ]
)

