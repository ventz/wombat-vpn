// swift-tools-version: 6.0
import PackageDescription

// Pure logic shared by the app, the packet tunnel extension and the CLI: wg-quick parsing,
// validation, keys, runtime statistics and the CLI control protocol. No AppKit, no
// NetworkExtension, so `swift test` covers all of it.
let package = Package(
    name: "TunnelCore",
    platforms: [.macOS(.v15)],
    products: [.library(name: "TunnelCore", targets: ["TunnelCore"])],
    targets: [
        .target(name: "TunnelCore"),
        .testTarget(name: "TunnelCoreTests", dependencies: ["TunnelCore"]),
    ],
    swiftLanguageModes: [.v6]
)
