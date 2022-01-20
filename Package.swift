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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.7.0@swift-5/AGDnsProxy-apple-1.7.0.zip",
      checksum: "e4e7b0719e224fbff094805f678aee92864cf54730c434803d85f4de382e4003"
    ),
  ]
)

