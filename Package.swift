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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.17@swift-5/AGDnsProxy-apple-2.5.17.zip",
      checksum: "7ba790c775ea7deb39fc4c8ca4273d4f6d35bf4b2cb28ad1de1eda9b24226d8e"
    ),
  ]
)

