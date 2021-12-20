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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.72@swift-5/AGDnsProxy-apple-1.6.72.zip",
      checksum: "e81af4ae90a87edfe9e9451bb29b321f0862a294550cb29cd8882f9d8c23f1c9"
    ),
  ]
)

