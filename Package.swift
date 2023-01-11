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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.73@swift-5/AGDnsProxy-apple-2.0.73.zip",
      checksum: "dcfdfccf5e8ab2848d498f648488921179914f17c6a41ed7c2fdf3c1b0ba0caa"
    ),
  ]
)

