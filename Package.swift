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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.24@swift-5/AGDnsProxy-apple-1.5.24.zip",
      checksum: "a99e08e546de33ff4d653d034ee67b1e2ff45b141e1768ea2eb2e2e86f0254c0"
    ),
  ]
)

