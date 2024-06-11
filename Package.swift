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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.33@swift-5/AGDnsProxy-apple-2.5.33.zip",
      checksum: "78bc013b49d76b0ea98ff7b3370282314131623eeafe1ea2555b654f443caf3c"
    ),
  ]
)

