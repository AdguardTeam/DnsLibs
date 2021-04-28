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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v1.5.21@swift-5/AGDnsProxy-apple-1.5.21.zip",
      checksum: "8041ee2a396e2cc0dc7e5f2ff3041d36d72a81125b30d7269d35032953342b9c"
    ),
  ]
)

