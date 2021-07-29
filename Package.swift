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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.19@swift-5/AGDnsProxy-apple-1.6.19.zip",
      checksum: "7cc2a1c74c03041753359aef7e49eb248f9a41ac5a4f6e0f53307b256e77de0e"
    ),
  ]
)

