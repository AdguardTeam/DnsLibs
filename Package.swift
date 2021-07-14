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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.14@swift-5/AGDnsProxy-apple-1.6.14.zip",
      checksum: "d4f97df14c56640c91b6a6d28ddf4d99de9f8e4f5955a028cc3db08737703499"
    ),
  ]
)

