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
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.8.0")),
//        .package(url: "git@github.com:needle-tail/double-ratchet-kit.git", branch: "main"),
        .package(path: "../double-ratchet-kit"),
        .package(path: "../needletail-crypto")
//        .package(url: "git@github.com:needle-tail/needletail-crypto.git", branch: "main")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "CryptoSession", dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
                .product(name: "NeedleTailCrypto", package: "needletail-crypto")
                
            ]),
        .testTarget(
            name: "CryptoSessionTests",
            dependencies: ["CryptoSession"]
        ),
    ]
)
