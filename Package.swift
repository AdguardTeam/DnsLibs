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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.53@swift-5/AGDnsProxy-apple-1.6.53.zip",
      checksum: "f5371645263222a2a5cf4678612c967b67b4c5085dca3dee1d84e7478db2455c"
    ),
  ]
)

