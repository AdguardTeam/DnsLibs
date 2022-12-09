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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.66@swift-5/AGDnsProxy-apple-2.0.66.zip",
      checksum: "e7bbe06f21734a8572b6917e670fe568d16b8529f3603581f0d452ab6c9ae6aa"
    ),
  ]
)

