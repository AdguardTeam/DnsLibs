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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.36@swift-5/AGDnsProxy-apple-2.2.36.zip",
      checksum: "60d18c5a006bf955ac80f98ac52ad0e1106e0b27e4fbf75dd5c140d4e3b0125f"
    ),
  ]
)

