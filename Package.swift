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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.8.25@swift-5/AGDnsProxy-apple-2.8.25.zip",
      checksum: "e391e12d48a50725b181783590c815d7675f86935fc144ce964ee86c9b3bc95b"
    ),
  ]
)

