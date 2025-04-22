// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "crypto-session",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "CryptoSession",
            targets: ["CryptoSession"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.12.3")),
        .package(url: "git@github.com:needle-tail/double-ratchet-kit.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "git@github.com:needle-tail/needletail-crypto.git", .upToNextMajor(from: "1.0.12")),
        .package(url: "git@github.com:needle-tail/needletail-logger.git", .upToNextMajor(from: "3.0.0")),
        .package(url: "git@github.com:needletails/needletail-algorithms.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "CryptoSession", dependencies: [
                "SessionEvents",
                "SessionModels",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
                .product(name: "NeedleTailCrypto", package: "needletail-crypto"),
                .product(name: "NeedleTailLogger", package: "needletail-logger"),
                .product(name: "NeedleTailAlgorithms", package: "needletail-algorithms")
                
            ]),
        .target(name: "SessionEvents", dependencies: [
            "SessionModels",
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit")
        ]),
        .target(name: "SessionModels", dependencies: [
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit")
        ]),
        .testTarget(
            name: "CryptoSessionTests",
            dependencies: ["CryptoSession"]
        ),
    ]
)
