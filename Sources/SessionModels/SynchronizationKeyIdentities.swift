//
//  SynchronizationKeyIdentities.swift
//  post-quantum-solace
//
//  Created by Cole M on 7/7/25.
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

/// A structure representing cryptographic key identities for synchronization operations.
///
/// This struct contains the identifiers for both sender and recipient cryptographic keys
/// used in the Double Ratchet protocol. It supports both classical (Curve25519) and
/// post-quantum (Kyber) key types for secure message synchronization.
///
/// ## Key Components
/// - **Sender Keys**: Optional identifiers for the sender's Curve25519 and Kyber keys
/// - **Recipient Keys**: Required identifiers for the recipient's Curve25519 and Kyber keys
/// - **Synchronization**: Used to coordinate key updates and message ordering
///
/// ## Usage
/// ```swift
/// let keyIds = SynchronizationKeyIdentities(
///     senderCurveId: "curve-sender-123",
///     senderKyberId: "kyber-sender-456",
///     recipientCurveId: "curve-recipient-789",
///     recipientKyberId: "kyber-recipient-012"
/// )
/// ```
///
/// ## Thread Safety
/// This struct is `Sendable` and can be safely passed between concurrent contexts.
/// All properties are immutable or use value semantics for thread safety.
///
/// ## Serialization
/// Uses obfuscated coding keys for BSON serialization to enhance security
/// and reduce payload size during network transmission.
public struct SynchronizationKeyIdentities: Sendable, Codable {
    /// Optional identifier for the sender's Curve25519 public key.
    ///
    /// This identifier is used to track the specific Curve25519 key used by the sender
    /// for message encryption. It may be `nil` if the sender's key is not yet established
    /// or if using a different key type.
    public var senderCurveId: String?

    /// Optional identifier for the sender's Kyber public key.
    ///
    /// This identifier is used to track the specific Kyber key used by the sender
    /// for post-quantum key exchange. It may be `nil` if the sender's Kyber key is not
    /// yet established or if using a different key type.
    public var senderKyberId: String?

    /// Required identifier for the recipient's Curve25519 public key.
    ///
    /// This identifier is used to identify the specific Curve25519 key that the recipient
    /// should use for message decryption. It is required for proper message routing.
    public let recipientCurveId: String

    /// Required identifier for the recipient's Kyber public key.
    ///
    /// This identifier is used to identify the specific Kyber key that the recipient
    /// should use for post-quantum key exchange. It is required for proper message routing.
    public let recipientKyberId: String

    /// Coding keys for BSON serialization with obfuscated field names.
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case senderCurveId = "a"
        case senderKyberId = "b"
        case recipientCurveId = "c"
        case recipientKyberId = "d"
    }

    /// Initializes a new instance of `SynchronizationKeyIdentities`.
    ///
    /// - Parameters:
    ///   - senderCurveId: Optional identifier for the sender's Curve25519 key
    ///   - senderKyberId: Optional identifier for the sender's Kyber key
    ///   - recipientCurveId: Required identifier for the recipient's Curve25519 key
    ///   - recipientKyberId: Required identifier for the recipient's Kyber key
    public init(
        senderCurveId: String? = nil,
        senderKyberId: String? = nil,
        recipientCurveId: String,
        recipientKyberId: String
    ) {
        self.senderCurveId = senderCurveId
        self.senderKyberId = senderKyberId
        self.recipientCurveId = recipientCurveId
        self.recipientKyberId = recipientKyberId
    }
}
