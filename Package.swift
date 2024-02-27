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
      url: "https://github.com/AdguardTeam/DnsLibs/releases/download/v2.5.3@swift-5/AGDnsProxy-apple-2.5.3.zip",
      checksum: "66da919d0797ce0af0d191f9bc299c3bfc92ac46a62317787ca66d40f1ff5676"
    ),
  ]
)

