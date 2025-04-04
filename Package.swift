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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.6.0@swift-5/AGDnsProxy-apple-2.6.0.zip",
      checksum: "ea190ed123accef325a90387bbaa9bf7a3253ae3f6c2d8c452c4a59ad83016a8"
    ),
  ]
)

