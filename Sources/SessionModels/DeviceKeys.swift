//
//  DeviceKeys.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
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
//

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto

/// A struct representing the cryptographic keys associated with a device in the post-quantum secure messaging system.
///
/// `DeviceKeys` encapsulates all the cryptographic material needed for a device to participate in secure
/// communications, including both classical and post-quantum cryptographic keys. This struct supports
/// the hybrid approach combining traditional elliptic curve cryptography with post-quantum MLKEM KEM.
///
/// ## Key Components:
/// - **Device Identity**: Unique identifier for the device
/// - **Signing Keys**: For message authentication and digital signatures
/// - **Long-term Keys**: For establishing persistent secure channels
/// - **One-time Keys**: For forward secrecy and ephemeral key exchange
/// - **Post-Quantum Keys**: MLKEM KEM keys for quantum-resistant encryption
///
/// ## Conformance:
/// - `Codable`: Supports serialization for storage and transmission
/// - `Sendable`: Safe for concurrent access
/// - `Equatable`: Supports equality comparison
///
/// ## Security Considerations:
/// - All private keys should be stored securely and never exposed
/// - Keys should be rotated according to the `rotateKeysDate` schedule
/// - One-time keys should be consumed and replaced regularly
public struct DeviceKeys: Codable, Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    ///
    /// Uses single-letter keys to minimize serialized data size while maintaining
    /// readability in the code. This is particularly important for cryptographic
    /// data that may be transmitted frequently.
    enum CodingKeys: String, CodingKey {
        case deviceId = "a" // Device identifier
        case signingPrivateKey = "b" // Private signing key
        case longTermPrivateKey = "c" // Private long-term key
        case oneTimePrivateKeys = "d" // Private one-time keys
        case mlKEMOneTimePrivateKeys = "e" // Post-Quantum private keys
        case finalMLKEMPrivateKey = "f" // Final Post-Quantum private key
        case rotateKeysDate = "g" // Date to rotate the keys
        case deviceAuthMLDSA = "h" // ML-DSA-65 device JWT signing state
        case pendingOneTimeKeyConsumptions = "i" // Deferred OTK consumptions awaiting reverse-handshake confirmation
    }

    /// Unique identifier for the device.
    ///
    /// This UUID serves as the primary identifier for the device across the network.
    /// It should remain constant for the lifetime of the device and is used for
    /// routing messages and establishing device-specific secure channels.
    public let deviceId: UUID

    /// Data representing the private signing key of the device.
    ///
    /// **Per-device identity invariant.** Set exactly once at device registration via
    /// `init(...)`. After registration this key is immutable for the lifetime of the `DeviceID`
    /// and may NEVER be rewritten in response to any wire-format input (e.g. a master-issued
    /// reprovisioning bundle). The single exception is the **master device's** account-key
    /// compromise rotation, which must use `rotateAccountSigningKey(_:)` and is the only
    /// supported mutation path post-registration. Linked (non-master) devices have no
    /// legitimate path to mutate this field; if local state diverges from the per-device
    /// `signingPublicKey` the server holds, the device must be re-linked.
    public private(set) var signingPrivateKey: Data

    /// Data representing the private long-term key of the device.
    ///
    /// This key is used for establishing persistent secure channels and should be
    /// kept for extended periods. It provides the foundation for long-term
    /// cryptographic relationships between devices.
    public var longTermPrivateKey: Data

    /// Array of private one-time keys for the device.
    ///
    /// These keys provide forward secrecy by being used only once for ephemeral
    /// key exchange. They should be consumed and replaced regularly to maintain
    /// security. Each key is used for a single cryptographic operation.
    public var oneTimePrivateKeys: [X25519PrivateKey]

    /// Array of private MLKEM one-time keys for the device.
    ///
    /// These post-quantum keys provide quantum-resistant forward secrecy. Like
    /// classical one-time keys, they should be consumed and replaced regularly.
    /// They are used in combination with classical keys for hybrid security.
    public var mlKEMOneTimePrivateKeys: [MLKEMPrivateKey]

    /// Final private MLKEM key for the device.
    ///
    /// This is the last resort post-quantum key used when all one-time keys have
    /// been consumed. It should be replaced with new one-time keys as soon as
    /// possible to maintain optimal security.
    public var finalMLKEMPrivateKey: MLKEMPrivateKey

    /// Date to rotate the keys, if applicable.
    ///
    /// When this date is reached, the device should generate new cryptographic
    /// keys to maintain security. This is particularly important for long-term
    /// and signing keys that are used repeatedly.
    public var rotateKeysDate: Date?

    /// ML-DSA-65 device JWT signing state (seed + activation marker).
    ///
    /// Optional so session contexts persisted before the PQ JWT migration
    /// decode unchanged; the enrollment flow populates it lazily after the
    /// device authenticates. Mutate only through
    /// `updateDeviceAuthMLDSA(_:)`.
    public private(set) var deviceAuthMLDSA: DeviceAuthMLDSAState?

    /// Deferred one-time-key consumptions awaiting reverse-handshake confirmation.
    ///
    /// Strict OTK enforcement (4.1.0) marks a bootstrap's one-time keys as spent
    /// at first authenticated decrypt, but the private halves must stay resolvable
    /// until the initiator provably advances past the handshake — recovery replays
    /// the initiator's first encrypted frame. Each entry names the receive lane
    /// whose bootstrap consumed the keys; the first *committed* inbound frame on
    /// that lane without a one-time-key id deletes the private halves and clears
    /// the entry.
    ///
    /// Optional so session contexts persisted before 4.1.0 decode unchanged, and
    /// `nil` while nothing is pending so encodes stay byte-identical to 4.0.0.
    /// Mutate only through `recordPendingOneTimeKeyConsumption(_:)` and
    /// `removePendingOneTimeKeyConsumptions(for:)`.
    public private(set) var pendingOneTimeKeyConsumptions: [PendingOneTimeKeyConsumption]?

    /// Initializes a new instance of `DeviceKeys` with all required cryptographic material.
    ///
    /// This initializer creates a complete set of device keys for secure communication.
    /// All cryptographic keys should be generated using cryptographically secure
    /// random number generators and stored securely.
    ///
    /// - Parameters:
    ///   - deviceId: Unique identifier for the device that remains constant throughout its lifetime.
    ///   - signingPrivateKey: Private key used for digital signatures and message authentication.
    ///   - longTermPrivateKey: Private key used for establishing persistent secure channels.
    ///   - oneTimePrivateKeys: Array of ephemeral private keys for forward secrecy.
    ///   - mlKEMOneTimePrivateKeys: Array of post-quantum ephemeral private keys for quantum-resistant forward secrecy.
    ///   - finalMLKEMPrivateKey: Fallback post-quantum private key used when one-time keys are exhausted.
    ///   - rotateKeysDate: Optional date when keys should be rotated for security maintenance.
    public init(
        deviceId: UUID,
        signingPrivateKey: Data,
        longTermPrivateKey: Data,
        oneTimePrivateKeys: [X25519PrivateKey],
        mlKEMOneTimePrivateKeys: [MLKEMPrivateKey],
        finalMLKEMPrivateKey: MLKEMPrivateKey,
        rotateKeysDate: Date? = nil
    ) {
        self.deviceId = deviceId
        self.signingPrivateKey = signingPrivateKey
        self.longTermPrivateKey = longTermPrivateKey
        self.oneTimePrivateKeys = oneTimePrivateKeys
        self.mlKEMOneTimePrivateKeys = mlKEMOneTimePrivateKeys
        self.finalMLKEMPrivateKey = finalMLKEMPrivateKey
        self.rotateKeysDate = rotateKeysDate
    }

    /// Updates the key rotation date for the device.
    ///
    /// This method allows scheduling when cryptographic keys should be rotated
    /// to maintain security. The rotation date is typically set based on
    /// security policies and key usage patterns.
    ///
    /// - Parameter date: The new date when keys should be rotated.
    public mutating func updateRotateKeysDate(_ date: Date) async {
        rotateKeysDate = date
    }

    /// Master-device-only entry point for replacing the account signing key during compromise rotation.
    ///
    /// On master devices, `signingPrivateKey` plays a dual role: it is both the device's per-device
    /// signing key AND the account-level key used to sign each `SignedDeviceConfiguration` in the
    /// shared device list. A successful `rotateKeysOnPotentialCompromise()` must therefore replace
    /// it. This is the ONLY supported mutation post-registration, and it must never be invoked from
    /// a linked (non-master) device or in response to any wire-format input. Callers MUST first
    /// guard on `currentDevice.isMasterDevice` (the rotation function does so today).
    public mutating func rotateAccountSigningKey(_ data: Data) {
        signingPrivateKey = data
    }

    /// Replaces the ML-DSA-65 device JWT signing state. Pass `nil` to discard
    /// the key material (e.g. when the server reports the key was superseded).
    public mutating func updateDeviceAuthMLDSA(_ state: DeviceAuthMLDSAState?) {
        deviceAuthMLDSA = state
    }

    /// Records a deferred one-time-key consumption for a receive lane.
    /// Idempotent: re-recording an identical entry (bootstrap replay) is a no-op.
    public mutating func recordPendingOneTimeKeyConsumption(_ entry: PendingOneTimeKeyConsumption) {
        var entries = pendingOneTimeKeyConsumptions ?? []
        guard !entries.contains(entry) else { return }
        entries.append(entry)
        pendingOneTimeKeyConsumptions = entries
    }

    /// Removes and returns every pending consumption recorded for a receive lane.
    /// Resets the field to `nil` when the last entry is removed so encodes stay
    /// byte-identical to pre-4.1.0 blobs while nothing is pending.
    public mutating func removePendingOneTimeKeyConsumptions(for sessionIdentityId: UUID) -> [PendingOneTimeKeyConsumption] {
        guard var entries = pendingOneTimeKeyConsumptions else { return [] }
        let matched = entries.filter { $0.sessionIdentityId == sessionIdentityId }
        guard !matched.isEmpty else { return [] }
        entries.removeAll { $0.sessionIdentityId == sessionIdentityId }
        pendingOneTimeKeyConsumptions = entries.isEmpty ? nil : entries
        return matched
    }

    /// True while any remaining pending entry still names this X25519 one-time key.
    /// A sibling lane that bootstrapped with the same published key must keep the
    /// private half until that lane also confirms.
    public func isOneTimeKeyStillPending(_ id: UUID) -> Bool {
        (pendingOneTimeKeyConsumptions ?? []).contains { $0.oneTimeKeyId == id }
    }

    /// True while any remaining pending entry still names this MLKEM one-time key.
    public func isMLKEMOneTimeKeyStillPending(_ id: UUID) -> Bool {
        (pendingOneTimeKeyConsumptions ?? []).contains { $0.mlKEMOneTimeKeyId == id }
    }
}

/// A deferred one-time-key consumption: the keys an inbound PQXDH bootstrap
/// decrypt marked as spent, retained until the reverse handshake confirms.
///
/// The confirming event is protocol state, not elapsed time: the initiator keeps
/// citing the one-time-key id until it has processed the responder's first
/// authenticated reply, so the first committed inbound frame on the lane without
/// a one-time-key id proves the bootstrap can never legitimately replay again.
public struct PendingOneTimeKeyConsumption: Codable, Sendable, Equatable {
    enum CodingKeys: String, CodingKey {
        case sessionIdentityId = "a"
        case oneTimeKeyId = "b"
        case mlKEMOneTimeKeyId = "c"
    }

    /// The receive lane (session identity) whose bootstrap consumed the keys.
    public let sessionIdentityId: UUID

    /// X25519 one-time private key pending deletion, if the bootstrap cited one.
    public let oneTimeKeyId: UUID?

    /// MLKEM one-time private key pending deletion, if the bootstrap cited a
    /// pool key. Always `nil` when the final (last-resort) MLKEM key was used —
    /// that key is never consumed.
    public let mlKEMOneTimeKeyId: UUID?

    public init(sessionIdentityId: UUID, oneTimeKeyId: UUID?, mlKEMOneTimeKeyId: UUID?) {
        self.sessionIdentityId = sessionIdentityId
        self.oneTimeKeyId = oneTimeKeyId
        self.mlKEMOneTimeKeyId = mlKEMOneTimeKeyId
    }
}

/// Client-side state for the ML-DSA-65 device JWT key: the 32-byte FIPS 204
/// seed the private key is derived from, and the server-confirmed `kid` once
/// activation completes. Tokens are minted with this key only after
/// `activatedKid` is set.
public struct DeviceAuthMLDSAState: Codable, Sendable, Equatable {
    enum CodingKeys: String, CodingKey {
        case seed = "a"
        case activatedKid = "b"
    }

    /// FIPS 204 ML-DSA-65 private key seed (32 bytes).
    public let seed: Data

    /// The `kid` the server activated for this key; nil while enrollment is
    /// pending or incomplete.
    public private(set) var activatedKid: String?

    public init(seed: Data, activatedKid: String? = nil) {
        self.seed = seed
        self.activatedKid = activatedKid
    }

    public mutating func markActivated(kid: String) {
        activatedKid = kid
    }
}
