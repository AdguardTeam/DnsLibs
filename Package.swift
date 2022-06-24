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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.32@swift-5/AGDnsProxy-apple-1.7.32.zip",
      checksum: "16862cabef76462369ee7c169c01cb8809572703a9bce4213e7244d404f35c1c"
    ),
  ]
)

