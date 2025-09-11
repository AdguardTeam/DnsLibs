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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.6.20@swift-5/AGDnsProxy-apple-2.6.20.zip",
      checksum: "a9cc086960b7808eac788494b5bceafe45bd2862225af7d699e6be2bf82512e6"
    ),
  ]
)

