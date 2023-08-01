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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.17@swift-5/AGDnsProxy-apple-2.2.17.zip",
      checksum: "d4ac047ec297f55f477e7ad2ed6c1d8b967b6139560834486b41411b68502477"
    ),
  ]
)

