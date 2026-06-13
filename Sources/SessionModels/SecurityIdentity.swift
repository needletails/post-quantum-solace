//
//  SecurityIdentity.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import Crypto
import Foundation

/// Stable, account-level identity used for out-of-band trust verification between
/// two users (Safety numbers).
///
/// A `SecurityIdentity` is the pair `(secretName, signingPublicKey)` of a user's
/// **account-level** signing key (the long-term key that signs every device a user
/// adds). When the master device rotates this key — or when a server-side identity
/// swap is attempted — the safety number visibly changes, allowing two users to
/// re-verify each other through a side channel (in-person scan, voice call, etc.).
///
/// ## Two layers of trust
/// - **TOFU (automatic):** the SDK pins the account `signingPublicKey` per peer
///   identity (see `PeerIdentityRefreshAssessment`) and per local account (see
///   `PQSSession.adoptVerifiedUserConfiguration`). Silent server-side rotation is
///   rejected.
/// - **Safety number (manual):** users compare `safetyNumber(local:remote:)` out
///   of band to confirm no MITM exists between them.
///
/// ## Determinism
/// `safetyNumber(local:remote:)` is symmetric — both sides see the same digits
/// regardless of who is rendering it — and deterministic for a fixed
/// `(secretName, signingPublicKey)` pair.
public struct SecurityIdentity: Hashable, Sendable {
    /// Stable per-user identifier (e.g. the user's secret name / handle).
    public let secretName: String
    /// Account-level signing public key (raw representation).
    public let signingPublicKey: Data

    public init(secretName: String, signingPublicKey: Data) {
        self.secretName = secretName
        self.signingPublicKey = signingPublicKey
    }

    /// Convenience: derive the security identity from a `UserConfiguration`.
    public init(secretName: String, configuration: UserConfiguration) {
        self.init(secretName: secretName, signingPublicKey: configuration.signingPublicKey)
    }

    // MARK: - Fingerprint

    /// Iterated SHA-512 fingerprint over `(versionLE || signingPublicKey || secretName)`.
    ///
    /// Iteration count the numeric fingerprint generator's default
    /// (5200) Returns the full 64-byte digest; callers typically slice the first 30 bytes for
    /// display.
    public func fingerprint(version: UInt32 = 1, iterations: Int = 5200) -> Data {
        precondition(iterations > 0, "iterations must be > 0")
        var versionLE = version.littleEndian
        let versionBytes = withUnsafeBytes(of: &versionLE) { Data($0) }
        let nameBytes = Data(secretName.utf8)

        var hashInput = Data()
        hashInput.append(versionBytes)
        hashInput.append(signingPublicKey)
        hashInput.append(nameBytes)

        var current = Data(SHA512.hash(data: hashInput))
        for _ in 1 ..< iterations {
            // Re-mix the original key + name on every round so the digest depends
            // on the identity even after many iterations
            var next = Data()
            next.append(current)
            next.append(signingPublicKey)
            next.append(nameBytes)
            current = Data(SHA512.hash(data: next))
        }
        return current
    }

    /// Short, colon-grouped hex fingerprint suitable for compact UI badges.
    /// Defaults to the first 8 bytes of the iterated fingerprint.
    public func shortFingerprintHex(byteCount: Int = 8) -> String {
        precondition((1 ... 32).contains(byteCount), "byteCount must be 1...32")
        let prefix = fingerprint().prefix(byteCount)
        return prefix
            .map { String(format: "%02X", $0) }
            .chunked(into: 2)
            .map { $0.joined() }
            .joined(separator: ":")
    }

    // MARK: - Safety number

    /// Render a 60-digit safety number between two identities.
    ///
    /// The result is symmetric: `safetyNumber(local: a, remote: b)` equals
    /// `safetyNumber(local: b, remote: a)`. Display format is 12 groups of 5
    /// digits separated by spaces ("Safety Number" UI):
    /// `12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890`.
    public static func safetyNumber(
        local: SecurityIdentity,
        remote: SecurityIdentity,
        version: UInt32 = 1,
        iterations: Int = 5200
    ) -> String {
        let localFp = local.fingerprint(version: version, iterations: iterations)
        let remoteFp = remote.fingerprint(version: version, iterations: iterations)

        // Symmetric ordering: lexicographically smallest fingerprint goes first.
        let (firstFp, secondFp): (Data, Data) = {
            for (l, r) in zip(localFp, remoteFp) {
                if l < r { return (localFp, remoteFp) }
                if l > r { return (remoteFp, localFp) }
            }
            return (localFp, remoteFp)
        }()

        let firstDigits = displayDigits(from: firstFp)
        let secondDigits = displayDigits(from: secondFp)
        let raw = firstDigits + secondDigits
        return raw.chunked(into: 5).map(String.init).joined(separator: " ")
    }

    /// Six 5-digit chunks (30 digits) extracted from the first 30 bytes of the
    /// fingerprint`getDisplayStringFor`.
    private static func displayDigits(from fingerprint: Data) -> String {
        precondition(fingerprint.count >= 30, "fingerprint must be at least 30 bytes")
        var output = ""
        output.reserveCapacity(30)
        let bytes = Array(fingerprint.prefix(30))
        for chunkIndex in 0 ..< 6 {
            let offset = chunkIndex * 5
            // Read 5 big-endian bytes into a UInt64 and modulo 100_000.
            var value: UInt64 = 0
            for i in 0 ..< 5 {
                value = (value << 8) | UInt64(bytes[offset + i])
            }
            output += String(format: "%05d", value % 100_000)
        }
        return output
    }
}

// MARK: - Helpers

private extension String {
    /// Split into substrings of length `size`. Final chunk may be shorter.
    func chunked(into size: Int) -> [Substring] {
        precondition(size > 0)
        var result: [Substring] = []
        var idx = startIndex
        while idx < endIndex {
            let end = index(idx, offsetBy: size, limitedBy: endIndex) ?? endIndex
            result.append(self[idx ..< end])
            idx = end
        }
        return result
    }
}

private extension Array where Element == String {
    /// Group an array of single-character hex strings into pairs.
    func chunked(into size: Int) -> [[Element]] {
        precondition(size > 0)
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0 ..< Swift.min($0 + size, count)])
        }
    }
}
