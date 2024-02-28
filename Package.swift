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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.4@swift-5/AGDnsProxy-apple-2.5.4.zip",
      checksum: "26a4462b23930557d8c0f91fa29930176ab0d7573e67973a475359b6506f885c"
    ),
  ]
)

