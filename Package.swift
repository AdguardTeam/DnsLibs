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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.44@swift-5/AGDnsProxy-apple-1.5.44.zip",
      checksum: "83d69616595401b6dc417bade4d11577833da3c17f063dc44f914559dfcca812"
    ),
  ]
)

