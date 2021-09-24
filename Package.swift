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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.46@swift-5/AGDnsProxy-apple-1.6.46.zip",
      checksum: "d0383e35d7a88cfae922764bdbf52ebc48e15c7f8a82c4835508b95e27882bbc"
    ),
  ]
)

