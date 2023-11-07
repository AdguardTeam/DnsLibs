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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.0@swift-5/AGDnsProxy-apple-2.4.0.zip",
      checksum: "b31f4c1d94756429721bacfccfa81ab90b382c0f181d4cd4cd544a63ce17fb66"
    ),
  ]
)

