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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.8.17@swift-5/AGDnsProxy-apple-2.8.17.zip",
      checksum: "8464bf17888a722a0fb230416879ef8ced0fe73f6a524ea159a5c48ee2b620a5"
    ),
  ]
)

