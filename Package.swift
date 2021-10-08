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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.54@swift-5/AGDnsProxy-apple-1.6.54.zip",
      checksum: "2fc0a97e398ca412d962303b6c1377ee1b02b9db16fdec9f8f1f57b286d64eaa"
    ),
  ]
)

