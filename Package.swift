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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.43@swift-5/AGDnsProxy-apple-1.7.43.zip",
      checksum: "b6ae52be1da491341a9a3c73763d4bdef565674e8858ef1abf921bfeda74d88e"
    ),
  ]
)

