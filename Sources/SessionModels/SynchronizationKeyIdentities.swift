//
//  SynchronizationKeyIdentities.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-07-07.
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
/// post-quantum (MLKEM) key types for secure message synchronization.
///
/// ## Key Components
/// - **Sender Keys**: Optional identifiers for the sender's Curve25519 and MLKEM keys
/// - **Recipient Keys**: Required identifiers for the recipient's Curve25519 and MLKEM keys
/// - **Synchronization**: Used to coordinate key updates and message ordering
///
/// ## Usage
/// ```swift
/// let keyIds = SynchronizationKeyIdentities(
///     senderCurveId: "curve-sender-123",
///     senderMLKEMId: "mlKEM-sender-456",
///     recipientCurveId: "curve-recipient-789",
///     recipientMLKEMId: "mlKEM-recipient-012"
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

    /// Optional identifier for the sender's MLKEM public key.
    ///
    /// This identifier is used to track the specific MLKEM key used by the sender
    /// for post-quantum key exchange. It may be `nil` if the sender's MLKEM key is not
    /// yet established or if using a different key type.
    public var senderMLKEMId: String?

    /// Required identifier for the recipient's Curve25519 public key.
    ///
    /// This identifier is used to identify the specific Curve25519 key that the recipient
    /// should use for message decryption. It is required for proper message routing.
    public let recipientCurveId: String

    /// Required identifier for the recipient's MLKEM public key.
    ///
    /// This identifier is used to identify the specific MLKEM key that the recipient
    /// should use for post-quantum key exchange. It is required for proper message routing.
    public let recipientMLKEMId: String

    /// Coding keys for BSON serialization with obfuscated field names.
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case senderCurveId = "a"
        case senderMLKEMId = "b"
        case recipientCurveId = "c"
        case recipientMLKEMId = "d"
    }

    /// Initializes a new instance of `SynchronizationKeyIdentities`.
    ///
    /// - Parameters:
    ///   - senderCurveId: Optional identifier for the sender's Curve25519 key
    ///   - senderMLKEMId: Optional identifier for the sender's MLKEM key
    ///   - recipientCurveId: Required identifier for the recipient's Curve25519 key
    ///   - recipientMLKEMId: Required identifier for the recipient's MLKEM key
    public init(
        senderCurveId: String? = nil,
        senderMLKEMId: String? = nil,
        recipientCurveId: String,
        recipientMLKEMId: String
    ) {
        self.senderCurveId = senderCurveId
        self.senderMLKEMId = senderMLKEMId
        self.recipientCurveId = recipientCurveId
        self.recipientMLKEMId = recipientMLKEMId
    }
}

public enum TransportEvent: Sendable, Codable {
    case sessionReestablishment
    case synchronizeOneTimeKeys(SynchronizationKeyIdentities)
    
    enum CodingKeys: String, CodingKey {
        case sessionReestablishment = "a"
        case synchronizeOneTimeKeys = "b"
    }
}
