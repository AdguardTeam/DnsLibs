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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.17@swift-5/AGDnsProxy-apple-1.6.17.zip",
      checksum: "2bb77365dd4ff875ddd6cb8692d1a89faf6b8eb8084d99f276638c255646a863"
    ),
  ]
)

