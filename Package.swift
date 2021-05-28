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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.38@swift-5/AGDnsProxy-apple-1.5.38.zip",
      checksum: "f4a6cb8798fee62bf185d944afb83a5f977972c51282089a47dd9ed29d8a1aa4"
    ),
  ]
)

