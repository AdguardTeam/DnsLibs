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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.1.26@swift-5/AGDnsProxy-apple-2.1.26.zip",
      checksum: "2e1027f346ec2554b3fb64713f6475838c72e4bff0f58ce4f3980d6270e78aa8"
    ),
  ]
)

