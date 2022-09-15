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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.0.14@swift-5/AGDnsProxy-apple-2.0.14.zip",
      checksum: "93505194b0f04a754599fb7c5c8ce4a740e2f20d3e94dc481891e1c8c573262f"
    ),
  ]
)

