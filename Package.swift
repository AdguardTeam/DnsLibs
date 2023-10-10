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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.3.4@swift-5/AGDnsProxy-apple-2.3.4.zip",
      checksum: "d2f70bdebacf360de8bf36da7b6d0fdf018787c2d472ed3d0e00d0e56451f90d"
    ),
  ]
)

