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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.75@swift-5/AGDnsProxy-apple-2.0.75.zip",
      checksum: "8f7a7929e59dc412351e60a49e3e0bb33ec172a1a5d89df3d0d8729fd637d7e4"
    ),
  ]
)

