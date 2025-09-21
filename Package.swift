// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "swift-secretstore",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9)
    ],
    products: [
        .library(
            name: "SecretStore",
            targets: ["SecretStore"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.5.0")
    ],
    targets: [
        .target(
            name: "SecretStore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(
            name: "SecretStoreTests",
            dependencies: ["SecretStore"]
        )
    ]
)
