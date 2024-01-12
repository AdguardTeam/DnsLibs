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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.38@swift-5/AGDnsProxy-apple-2.4.38.zip",
      checksum: "ef91e6c9eb1027fb71f3488eb77ba4239c882e97214b9d24bbdb40b61af6e134"
    ),
  ]
)

