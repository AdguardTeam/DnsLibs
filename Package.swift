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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.34@swift-5/AGDnsProxy-apple-2.5.34.zip",
      checksum: "1698691956333e472e1de6e7efffc31305cbdc93c9a809cf33e29bdb9a86f143"
    ),
  ]
)

