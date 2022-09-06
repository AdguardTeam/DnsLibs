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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.5@swift-5/AGDnsProxy-apple-2.0.5.zip",
      checksum: "7e1de31679b97cd4b712e61bfe2200d980a9b4897319e689355026c28723a969"
    ),
  ]
)

