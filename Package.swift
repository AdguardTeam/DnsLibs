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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.4@swift-5/AGDnsProxy-apple-1.7.4.zip",
      checksum: "f9a2ec105d70329aa7e675b2dbc0485d5e0f7db1d63376c128c0a8ea8be61262"
    ),
  ]
)

