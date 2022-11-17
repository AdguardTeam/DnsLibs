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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.58@swift-5/AGDnsProxy-apple-2.0.58.zip",
      checksum: "abd4950b391168d46f60bf3a2e1e05c817703a1f215f13857baf4dfadb5e0077"
    ),
  ]
)

