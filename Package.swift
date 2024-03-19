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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.8@swift-5/AGDnsProxy-apple-2.5.8.zip",
      checksum: "d99cc94a36159a13dac51ce122178d372e1942a24a3ff44ab16a2819c12a6ef6"
    ),
  ]
)

