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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.22@swift-5/AGDnsProxy-apple-2.0.22.zip",
      checksum: "c21c617a55cd4690384b49a0d8b703751249b2c7e908ca5acbbf43a920f450ac"
    ),
  ]
)

