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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.18@swift-5/AGDnsProxy-apple-2.0.18.zip",
      checksum: "3c1e12c77420a8358b8241354bf3a1d153b90b61ba9ba61dce1a5df86e908cfe"
    ),
  ]
)

