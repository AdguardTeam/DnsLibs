// swift-tools-version:5.9
// Template manifest for the AGDnsProxy SwiftPM binary distribution. The build
// job substitutes @VERSION@, @AK_BASE@ (Artifact Keeper base URL) and @CHECKSUM@
// (sha256 of the published AGDnsProxy.zip) before packaging.
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
      url: "@AK_BASE@/api/v1/repositories/apple-bin-virtual/download/core.dns-libs/@VERSION@/AGDnsProxy.zip",
      checksum: "@CHECKSUM@"
    ),
  ]
)
