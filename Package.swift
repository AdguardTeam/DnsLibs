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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.60@swift-5/AGDnsProxy-apple-1.6.60.zip",
      checksum: "4004998ce2390678552fb334c0dfe2e1cb134940ef32610d533bbe63f866a23c"
    ),
  ]
)

