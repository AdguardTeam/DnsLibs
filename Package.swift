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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.8.19@swift-5/AGDnsProxy-apple-2.8.19.zip",
      checksum: "f6c107416e378c32f449e97e23df3ada242969d104c0e786a1234bfaf481b8fb"
    ),
  ]
)

