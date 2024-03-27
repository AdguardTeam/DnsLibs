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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.12@swift-5/AGDnsProxy-apple-2.5.12.zip",
      checksum: "abaf7beb67cb363efda19295e1f9f8a9c4847c497cb18c15f71625a712a065e9"
    ),
  ]
)

