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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.35@swift-5/AGDnsProxy-apple-1.5.35.zip",
      checksum: "8127393a3695e0619ca74ec798024c84e03f08ce652c4e6518e3874d80ae4243"
    ),
  ]
)

