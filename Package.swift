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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.3.8@swift-5/AGDnsProxy-apple-2.3.8.zip",
      checksum: "50aa4aa53a5ef8ebfebac316eb84dfe38e844cc38e6ccf79c79290461eacc8f2"
    ),
  ]
)

