// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "post-quantum-solace",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "PostQuantumSolace",
            targets: ["PQSSession"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.12.3")),
//        .package(url: "https://github.com/needletails/double-ratchet-kit.git", .upToNextMajor(from: "1.0.0")),
        .package(path: "../double-ratchet-kit"),
        .package(url: "https://github.com/needletails/needletail-crypto.git", .upToNextMajor(from: "1.0.12")),
        .package(url: "https://github.com/needletails/needletail-logger.git", .upToNextMajor(from: "3.0.0")),
        .package(url: "https://github.com/needletails/needletail-algorithms.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        .target(
            name: "PQSSession", dependencies: [
                "SessionEvents",
                "SessionModels",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
                .product(name: "NeedleTailCrypto", package: "needletail-crypto"),
                .product(name: "NeedleTailLogger", package: "needletail-logger"),
                .product(name: "NeedleTailAlgorithms", package: "needletail-algorithms"),
            ]
        ),
        .target(name: "SessionEvents", dependencies: [
            "SessionModels",
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
        ]),
        .target(name: "SessionModels", dependencies: [
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
        ]),
        .testTarget(
            name: "PostQuantumSolaceTests",
            dependencies: ["PQSSession"]
        ),
    ]
)
