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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.19@swift-5/AGDnsProxy-apple-2.5.19.zip",
      checksum: "630c1455c76d4f3c8ab8703853206bc5c5bda95e7e89fb803316928470a35e57"
    ),
  ]
)

