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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.9@swift-5/AGDnsProxy-apple-1.5.9.zip",
      checksum: "8438782352f53839875ca9fd686d48be94a2a93bb35bdf26a1d030fcf9a989bc"
    ),
  ]
)

