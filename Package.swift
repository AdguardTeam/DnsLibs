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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.48@swift-5/AGDnsProxy-apple-2.0.48.zip",
      checksum: "8da6f5b763c34a86cee2568ee044e7075c97f35749087a93e77bdff28c2e96fb"
    ),
  ]
)

