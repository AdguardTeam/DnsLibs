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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.4@swift-5/AGDnsProxy-apple-2.0.4.zip",
      checksum: "265b70db457120b6a69f97771e4984354cbb247fa70bb949a700da94d553e5dd"
    ),
  ]
)

