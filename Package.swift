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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.16@swift-5/AGDnsProxy-apple-1.6.16.zip",
      checksum: "f67ac2900f6fdd8760bd75bb1e2c6f3387c97782cc5a86bbc5ec4277ab727cbc"
    ),
  ]
)

