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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.17@swift-5/AGDnsProxy-apple-1.5.17.zip",
      checksum: "fa142b747fab578fb89fbc0bd6528942da8308ba8013a8cbdb986a182741480c"
    ),
  ]
)

