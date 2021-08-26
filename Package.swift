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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.29@swift-5/AGDnsProxy-apple-1.6.29.zip",
      checksum: "c5976c1aba4e75ff2e42d3e71e6c84e9b971d3909904cb8ba1c960af1256a2ca"
    ),
  ]
)

