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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.6.31@swift-5/AGDnsProxy-apple-1.6.31.zip",
      checksum: "d100adca3358ad0693cf72530a3bfb38b5ac377ae233d99df3be7527382ba426"
    ),
  ]
)

