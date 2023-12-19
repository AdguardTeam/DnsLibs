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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.4.34@swift-5/AGDnsProxy-apple-2.4.34.zip",
      checksum: "ff98d65c0c0ece4334f364013a5aeb81f01795d0ec1edb9bffd63b9956f7d919"
    ),
  ]
)

