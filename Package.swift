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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.1.27@swift-5/AGDnsProxy-apple-2.1.27.zip",
      checksum: "04333620f6cf538dd3c4cb154b9bca7deb1c25139753f858eee6cc96da047e39"
    ),
  ]
)

