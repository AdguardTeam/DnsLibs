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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.20@swift-5/AGDnsProxy-apple-2.0.20.zip",
      checksum: "a6b1e30fa9bbd51662c3fd7974988fcb0bc1c705467e89b7924844cb572e80df"
    ),
  ]
)

