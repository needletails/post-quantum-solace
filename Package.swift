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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.12.3"),
        .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "1.0.5"),
        .package(url: "https://github.com/needletails/needletail-logger.git", from: "3.1.1")
    ],
    targets: [
        .target(
            name: "PQSSession", dependencies: [
                "SessionEvents",
                "SessionModels",
                .product(name: "Crypto", package: "swift-crypto"),
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
        ]),
        .testTarget(
            name: "PostQuantumSolaceTests",
            dependencies: ["PQSSession"]
        ),
    ]
)
