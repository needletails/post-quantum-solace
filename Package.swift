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
        .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "2.0.1"),
        .package(url: "https://github.com/needletails/needletail-logger.git", from: "3.1.1"),
        .package(url: "https://github.com/needletails/needletail-algorithms.git", from: "2.0.4")
    ],
    targets: [
        .target(
            name: "PQSSession", dependencies: [
                "SessionEvents",
                "SessionModels",
                .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
                .product(name: "NeedleTailLogger", package: "needletail-logger")
            ]
        ),
        .target(name: "SessionEvents", dependencies: [
            "SessionModels",
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
        ]),
        .target(name: "SessionModels", dependencies: [
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
            .product(name: "NeedleTailAlgorithms", package: "needletail-algorithms")
        ]),
        .testTarget(
            name: "PostQuantumSolaceTests",
            dependencies: ["PQSSession"]
        ),
    ]
)
