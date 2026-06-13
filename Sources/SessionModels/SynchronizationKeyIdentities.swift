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

import Foundation

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
/// Uses obfuscated coding keys for Binary serialization to enhance security
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

    /// Coding keys for Binary serialization with obfuscated field names.
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

public enum SessionReestablishmentKind: String, Sendable, Codable {
    case peerRefresh = "a"
    case linkedDeviceRepair = "b"
    case linkedDeviceCompromiseObserved = "c"

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let legacyValue = try? container.decode(Bool.self) {
            self = legacyValue ? .linkedDeviceRepair : .peerRefresh
            return
        }

        let rawValue = try container.decode(String.self)
        guard let value = SessionReestablishmentKind(rawValue: rawValue) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid session reestablishment kind"
            )
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// Wire envelope for `SessionReestablishmentKind` carrying coalescing/idempotency metadata.
///
/// The receiver uses `(senderDeviceId, kind, intentId, epoch)` to dedupe redundant control
/// events that pile up in offline mailboxes and to coalesce same-episode re-emissions into
/// a single application-level reaction (e.g. one compromise prompt instead of N).
///
/// ## Compatibility
/// The custom `init(from:)` accepts both the new keyed encoding and a legacy bare
/// `SessionReestablishmentKind` payload, allowing in-flight messages from older SDK
/// versions to deserialize without metadata.
public struct SessionReestablishmentEnvelope: Sendable, Codable, Equatable {
    /// The semantic action requested by the sender.
    public let kind: SessionReestablishmentKind

    /// Stable identifier shared across every emission within a single sender-side episode.
    /// `nil` when decoded from a legacy bare-kind payload.
    public let intentId: UUID?

    /// Sender-side monotonically increasing counter (per-kind) for ordering and dedup.
    /// Receivers drop strictly-older epochs and treat equal epochs as duplicates.
    /// `0` when decoded from a legacy bare-kind payload.
    public let epoch: UInt64

    /// Sender's wall-clock at the moment this envelope was constructed.
    /// Used for diagnostics; receiver dedup decisions never depend on this value.
    public let emittedAt: Date

    /// True when this envelope acknowledges that the sender has processed an inbound
    /// reestablishment request and refreshed its local view.
    public let isResponse: Bool

    public init(
        kind: SessionReestablishmentKind,
        intentId: UUID? = nil,
        epoch: UInt64 = 0,
        emittedAt: Date = Date(),
        isResponse: Bool = false
    ) {
        self.kind = kind
        self.intentId = intentId
        self.epoch = epoch
        self.emittedAt = emittedAt
        self.isResponse = isResponse
    }

    private enum CodingKeys: String, CodingKey {
        // We persist `kind` as a raw `String` (its `rawValue`) rather than relying on
        // `SessionReestablishmentKind`'s custom Codable, because some binary serializers
        // track the wire type identity of nested Codable values and that interferes with
        // both round-tripping and tolerant cross-version decoding.
        case rawKind = "k"
        case intentId = "i"
        case epoch = "e"
        case emittedAt = "t"
        case isResponse = "r"
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: CodingKeys.self),
           let rawKind = try? container.decode(String.self, forKey: .rawKind),
           let kind = SessionReestablishmentKind(rawValue: rawKind) {
            self.kind = kind
            self.intentId = try? container.decodeIfPresent(UUID.self, forKey: .intentId)
            self.epoch = (try? container.decode(UInt64.self, forKey: .epoch)) ?? 0
            self.emittedAt = (try? container.decode(Date.self, forKey: .emittedAt)) ?? Date()
            self.isResponse = (try? container.decode(Bool.self, forKey: .isResponse)) ?? false
            return
        }
        // Legacy fallback for serializers that handed us a bare `SessionReestablishmentKind`.
        // In-flight pre-envelope payloads from older SDK builds land here.
        if let single = try? decoder.singleValueContainer(),
           let kind = try? single.decode(SessionReestablishmentKind.self) {
            self.kind = kind
            self.intentId = nil
            self.epoch = 0
            self.emittedAt = Date()
            self.isResponse = false
            return
        }
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Unrecognised SessionReestablishmentEnvelope payload"
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind.rawValue, forKey: .rawKind)
        try container.encodeIfPresent(intentId, forKey: .intentId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(emittedAt, forKey: .emittedAt)
        try container.encode(isResponse, forKey: .isResponse)
    }
}

public enum TransportEvent: Sendable, Codable {
    case sessionReestablishment(SessionReestablishmentEnvelope)
    case linkedDeviceReprovisioning(LinkedDeviceReprovisioningBundle)
    case synchronizeOneTimeKeys(SynchronizationKeyIdentities)
    case refreshOneTimeKeys
    case requestMessageResend(FailedMessageResendRequest)
    
    enum CodingKeys: String, CodingKey {
        case sessionReestablishment = "a"
        case linkedDeviceReprovisioning = "b"
        case synchronizeOneTimeKeys = "c"
        case refreshOneTimeKeys = "d"
        case requestMessageResend = "e"
    }
}

public struct FailedMessageResendRequest: Sendable, Codable {
    /// Maximum number of failed message ids carried in a single resend request.
    /// Enforced on both encode (init) and decode so a hostile peer cannot amplify
    /// replay work on the receiver with an oversized batch.
    public static let maxBatchedIds = 64

    public let failedSharedMessageId: String
    public let failedSharedMessageIds: [String]
    public let requestingDeviceId: UUID
    
    private enum CodingKeys: String, CodingKey {
        case failedSharedMessageId = "a"
        case requestingDeviceId = "b"
        case failedSharedMessageIds = "c"
    }
    
    public init(
        failedSharedMessageId: String,
        requestingDeviceId: UUID
    ) {
        self.failedSharedMessageId = failedSharedMessageId
        self.failedSharedMessageIds = [failedSharedMessageId]
        self.requestingDeviceId = requestingDeviceId
    }

    public init(
        failedSharedMessageIds: [String],
        requestingDeviceId: UUID
    ) {
        let ids = Self.normalizedIds(failedSharedMessageIds)
        self.failedSharedMessageId = ids.first ?? ""
        self.failedSharedMessageIds = ids
        self.requestingDeviceId = requestingDeviceId
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let single = try container.decodeIfPresent(String.self, forKey: .failedSharedMessageId)
        let batch = try container.decodeIfPresent([String].self, forKey: .failedSharedMessageIds)
        let ids = Self.normalizedIds(batch?.isEmpty == false ? batch! : single.map { [$0] } ?? [])
        guard let first = ids.first else {
            throw DecodingError.dataCorruptedError(
                forKey: .failedSharedMessageId,
                in: container,
                debugDescription: "Missing failed shared message id")
        }
        failedSharedMessageId = first
        failedSharedMessageIds = ids
        requestingDeviceId = try container.decode(UUID.self, forKey: .requestingDeviceId)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(failedSharedMessageId, forKey: .failedSharedMessageId)
        try container.encode(requestingDeviceId, forKey: .requestingDeviceId)
        if failedSharedMessageIds.count > 1 {
            try container.encode(failedSharedMessageIds, forKey: .failedSharedMessageIds)
        }
    }

    private static func normalizedIds(_ ids: [String]) -> [String] {
        var seen = Set<String>()
        var normalized: [String] = []
        for id in ids where !id.isEmpty && !seen.contains(id) {
            seen.insert(id)
            normalized.append(id)
            if normalized.count == Self.maxBatchedIds {
                break
            }
        }
        return normalized
    }
}
