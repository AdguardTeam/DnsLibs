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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.29@swift-5/AGDnsProxy-apple-1.7.29.zip",
      checksum: "53bf0749522d4b24365f0bd14a7365b9fb6674d57fe806e807879960a54e9c58"
    ),
  ]
)

