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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.52@swift-5/AGDnsProxy-apple-1.6.52.zip",
      checksum: "abdcb100e7099476625e71795e0f833ed1e874eb751c3366207d32c0d46132e6"
    ),
  ]
)

