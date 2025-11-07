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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.7.6@swift-5/AGDnsProxy-apple-2.7.6.zip",
      checksum: "b11a04a4dcdab89368430ed3e7e010f16ddb1cbc4bc321aafc77b3bb2cf502c7"
    ),
  ]
)

