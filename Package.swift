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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.35@swift-5/AGDnsProxy-apple-2.4.35.zip",
      checksum: "440aa8c6581d61badc0d551f509df5ffae40c27ed13a5acc8f910976860d78c8"
    ),
  ]
)

