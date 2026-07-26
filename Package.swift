// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import Foundation
import PackageDescription

// DecryptFailureAuditLog file trails (recovery + send/recv path).
// Local / staging dogfood: defined (Release dogfood keeps audits).
// Public App Store / customer Release: export PQS_STRIP_DECRYPT_FAILURE_AUDIT=1.
private let stripDecryptFailureAudit =
    ProcessInfo.processInfo.environment["PQS_STRIP_DECRYPT_FAILURE_AUDIT"] == "1"

private var pqsSessionSwiftSettings: [SwiftSetting] {
    guard !stripDecryptFailureAudit else { return [] }
    return [.define("PQS_DECRYPT_FAILURE_AUDIT")]
}

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
        .package(url: "https://github.com/needletails/binary-codable.git", from: "1.0.5"),
        // TODO: Before release, revert to the versioned dependency once the
        // RatchetState.receivedMessagesCount accessor ships in a tagged DRK release.
        // .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "3.2.0"),
        .package(path: "../double-ratchet-kit"),
        .package(url: "https://github.com/needletails/needletail-logger.git", from: "3.1.5"),
        .package(url: "https://github.com/needletails/needletail-algorithms.git", from: "2.0.5")
    ],
    targets: [
        .target(
            name: "PQSSession", dependencies: [
                "SessionEvents",
                "SessionModels",
                .product(name: "BinaryCodable", package: "binary-codable"),
                .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
                .product(name: "NeedleTailLogger", package: "needletail-logger")
            ],
            swiftSettings: pqsSessionSwiftSettings
        ),
        .target(name: "SessionEvents", dependencies: [
            "SessionModels",
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
        ]),
        .target(name: "SessionModels", dependencies: [
            .product(name: "BinaryCodable", package: "binary-codable"),
            .product(name: "DoubleRatchetKit", package: "double-ratchet-kit"),
            .product(name: "NeedleTailAlgorithms", package: "needletail-algorithms")
        ]),
        .testTarget(
            name: "PostQuantumSolaceTests",
            dependencies: [
                "PQSSession",
                .product(name: "BinaryCodable", package: "binary-codable")
            ]
        ),
    ]
)
