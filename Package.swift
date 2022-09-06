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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.7@swift-5/AGDnsProxy-apple-2.0.7.zip",
      checksum: "29cd24fa85ef8f214bc8a23228a836c06623dac0b5bbc3484ad877a9e0ab2cb4"
    ),
  ]
)

