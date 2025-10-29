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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.7.5@swift-5/AGDnsProxy-apple-2.7.5.zip",
      checksum: "0b3a57d2ba6e490161dcae78301ed001b0af040b31080c47eda9cadf079f8aea"
    ),
  ]
)

