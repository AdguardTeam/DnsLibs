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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.2.27@swift-5/AGDnsProxy-apple-2.2.27.zip",
      checksum: "fdf60c1612d4c130fd6993188fcbab29c04d2aee27e8a4d87f72477b8d0b5298"
    ),
  ]
)

