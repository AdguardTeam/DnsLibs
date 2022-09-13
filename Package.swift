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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.13@swift-5/AGDnsProxy-apple-2.0.13.zip",
      checksum: "d3586cbfc57e1f006c6f668cb4a0a037d7b763df65ba716dabe5c6203cb216ee"
    ),
  ]
)

