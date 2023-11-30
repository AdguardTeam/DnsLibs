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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.18@swift-5/AGDnsProxy-apple-2.4.18.zip",
      checksum: "2e53af46b5b53566b31aee2f05a3d401655b7ac23c4dc43c1fdde7841b4e844d"
    ),
  ]
)

