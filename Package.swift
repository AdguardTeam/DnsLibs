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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.37@swift-5/AGDnsProxy-apple-2.4.37.zip",
      checksum: "fc79b1683f56d2b27113953911068e6175a22be63151813ccbeb81baf5676196"
    ),
  ]
)

