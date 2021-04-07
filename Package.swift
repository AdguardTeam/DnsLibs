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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.7@swift-5/AGDnsProxy-apple-1.5.7.zip",
      checksum: "321a9c86479ff1517dc79a9ed4a9a639fad3447d6cea1bc7fdd48253e54bc3b6"
    ),
  ]
)

