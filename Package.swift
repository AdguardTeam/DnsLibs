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
      url: "https://github.com/sfionov/DnsLibs/releases/download/v1.5.5/AGDnsProxy-apple-1.5.5.zip",
      checksum: "807c85f89c3db1ea3c4bfd6bda8e121707d51835ec0ccb5a17ef327fefd07562"
    ),
  ]
)
