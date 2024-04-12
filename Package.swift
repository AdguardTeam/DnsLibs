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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.18@swift-5/AGDnsProxy-apple-2.5.18.zip",
      checksum: "d940e1d94d874e82d672ad4baeb1e3209c877dda49f0359e322563172b82905f"
    ),
  ]
)

