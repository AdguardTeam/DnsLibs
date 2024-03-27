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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.10@swift-5/AGDnsProxy-apple-2.5.10.zip",
      checksum: "9d15e6695f0f4a755a6c1c4942e46cd50754f11c282f6b428a035bb33e4ff696"
    ),
  ]
)

