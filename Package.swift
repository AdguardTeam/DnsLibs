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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.38@swift-5/AGDnsProxy-apple-1.6.38.zip",
      checksum: "e1c9ec08943df1b3853416b4d9c09d5073a1301c8c9a5b61e370f4c55f36c35f"
    ),
  ]
)

