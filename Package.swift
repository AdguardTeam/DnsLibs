// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "Setapp",
  platforms: [
    .iOS("10.0"), .macOS("10.12")
  ],
  products: [
    .library(name: "AGDnsProxy", targets: ["AGDnsProxy"]),
  ],
  targets: [
    .binaryTarget(
      name: "AGDnsProxy",
      url: "https://github.com/sfionov/DnsLibs/releases/download/1.5.5/AGDnsProxy-1.5.5.zip",
      checksum: "57ad4fa555df6ffd30e29849fd4c230962e39751e885ac573d24902b5c4a113c"
    ),
  ]
)
