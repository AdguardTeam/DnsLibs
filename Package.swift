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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.6.6@swift-5/AGDnsProxy-apple-2.6.6.zip",
      checksum: "74fe62c7d7d55365f222b90869ef68b2fac6a83a8402b0fc8972194968dc79e1"
    ),
  ]
)

