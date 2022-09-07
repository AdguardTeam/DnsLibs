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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.10@swift-5/AGDnsProxy-apple-2.0.10.zip",
      checksum: "0ea0096ff52b26c74485141d93813063f37229f375d73040e6c233e33bd685b3"
    ),
  ]
)

