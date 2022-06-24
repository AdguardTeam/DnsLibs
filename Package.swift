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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.31@swift-5/AGDnsProxy-apple-1.7.31.zip",
      checksum: "d4442935ecad4d46f8a0b20a4d65b56ca7afc99441fd4c10fa5343ad2fe7de91"
    ),
  ]
)

