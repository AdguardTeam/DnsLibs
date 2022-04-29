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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.28@swift-5/AGDnsProxy-apple-1.7.28.zip",
      checksum: "8e9aab2f4a30b741c5d4a9b648d7ad9f50a8d9b514dc7896fd24eca5def6171b"
    ),
  ]
)

