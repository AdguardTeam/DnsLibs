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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.36@swift-5/AGDnsProxy-apple-2.0.36.zip",
      checksum: "1f6956b2922c533285f7a7f571e1e11630d540b8a32917106642549f1c2e2a5a"
    ),
  ]
)

