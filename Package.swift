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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.26@swift-5/AGDnsProxy-apple-1.5.26.zip",
      checksum: "30f31fccf4d3132a75c568d51d1e45c9907cc13a7d49609b17ca040ebe507c13"
    ),
  ]
)

