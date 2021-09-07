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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.34@swift-5/AGDnsProxy-apple-1.6.34.zip",
      checksum: "3a6b578aa899b4ff31bbb61d6c5d89ca91823ed583b7b4be55bb23484d267f89"
    ),
  ]
)

