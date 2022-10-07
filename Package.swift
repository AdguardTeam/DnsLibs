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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.24@swift-5/AGDnsProxy-apple-2.0.24.zip",
      checksum: "be033ca61a37c5c9339d155466976fc74d5f2276d48a2cea259446d3f9a017d5"
    ),
  ]
)

