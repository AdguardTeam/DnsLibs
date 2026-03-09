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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.8.38@swift-5/AGDnsProxy-apple-2.8.38.zip",
      checksum: "0bdb178b733b377d5d4a694c923daa15e6b877cb5c9b0415c14a7a46d6b22e77"
    ),
  ]
)

