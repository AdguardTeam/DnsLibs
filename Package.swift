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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.34@swift-5/AGDnsProxy-apple-2.0.34.zip",
      checksum: "4636985b1fe2aec7bf6e80607d488547a0403322f6a4a8ee799835f6de10f0c6"
    ),
  ]
)

