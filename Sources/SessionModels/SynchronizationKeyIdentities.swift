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
import BinaryCodable

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
///     senderX25519Id: "curve-sender-123",
///     senderMLKEMId: "mlKEM-sender-456",
///     recipientX25519Id: "curve-recipient-789",
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
    public var senderX25519Id: String?

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
    public let recipientX25519Id: String

    /// Required identifier for the recipient's MLKEM public key.
    ///
    /// This identifier is used to identify the specific MLKEM key that the recipient
    /// should use for post-quantum key exchange. It is required for proper message routing.
    public let recipientMLKEMId: String

    /// Coding keys for Binary serialization with obfuscated field names.
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case senderX25519Id = "a"
        case senderMLKEMId = "b"
        case recipientX25519Id = "c"
        case recipientMLKEMId = "d"
    }

    /// Initializes a new instance of `SynchronizationKeyIdentities`.
    ///
    /// - Parameters:
    ///   - senderX25519Id: Optional identifier for the sender's Curve25519 key
    ///   - senderMLKEMId: Optional identifier for the sender's MLKEM key
    ///   - recipientX25519Id: Required identifier for the recipient's Curve25519 key
    ///   - recipientMLKEMId: Required identifier for the recipient's MLKEM key
    public init(
        senderX25519Id: String? = nil,
        senderMLKEMId: String? = nil,
        recipientX25519Id: String,
        recipientMLKEMId: String
    ) {
        self.senderX25519Id = senderX25519Id
        self.senderMLKEMId = senderMLKEMId
        self.recipientX25519Id = recipientX25519Id
        self.recipientMLKEMId = recipientMLKEMId
    }
}

public enum SessionReestablishmentKind: String, Sendable, Codable {
    case peerRefresh = "a"
    case linkedDeviceRepair = "b"
    case linkedDeviceCompromiseObserved = "c"
}

/// Wire envelope for `SessionReestablishmentKind` carrying coalescing/idempotency metadata.
///
/// The receiver uses `(senderDeviceId, kind, intentId, epoch)` to dedupe redundant control
/// events that pile up in offline mailboxes and to coalesce same-episode re-emissions into
/// a single application-level reaction (e.g. one compromise prompt instead of N).
///
/// Schema 2 rejects bare-kind payloads and the retired `requiresPreDecryptionReset` flag.
/// Stragglers reestablish.
public struct SessionReestablishmentEnvelope: Sendable, Codable, Equatable {
    /// The semantic action requested by the sender.
    public let kind: SessionReestablishmentKind

    /// Stable identifier shared across every emission within a single sender-side episode.
    public let intentId: UUID?

    /// Sender-side monotonically increasing counter (per-kind) for ordering and dedup.
    /// Receivers drop strictly-older epochs and treat equal epochs as duplicates.
    public let epoch: UInt64

    /// Sender's wall-clock at the moment this envelope was constructed.
    /// Used for diagnostics; receiver dedup decisions never depend on this value.
    public let emittedAt: Date

    /// True when this envelope acknowledges that the sender has processed an inbound
    /// reestablishment request and refreshed its local view.
    public let isResponse: Bool

    /// Concrete recipient device for device-scoped recovery. `nil` preserves
    /// account-wide refresh controls.
    public let targetDeviceId: UUID?

    public init(
        kind: SessionReestablishmentKind,
        intentId: UUID? = nil,
        epoch: UInt64 = 0,
        emittedAt: Date = Date(),
        isResponse: Bool = false,
        targetDeviceId: UUID? = nil
    ) {
        self.kind = kind
        self.intentId = intentId
        self.epoch = epoch
        self.emittedAt = emittedAt
        self.isResponse = isResponse
        self.targetDeviceId = targetDeviceId
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
        case targetDeviceId = "d"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawKind = try container.decode(String.self, forKey: .rawKind)
        guard let kind = SessionReestablishmentKind(rawValue: rawKind) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawKind,
                in: container,
                debugDescription: "Invalid session reestablishment kind"
            )
        }
        self.kind = kind
        self.intentId = try container.decodeIfPresent(UUID.self, forKey: .intentId)
        self.epoch = try container.decodeIfPresent(UInt64.self, forKey: .epoch) ?? 0
        self.emittedAt = try container.decodeIfPresent(Date.self, forKey: .emittedAt) ?? Date()
        self.isResponse = try container.decodeIfPresent(Bool.self, forKey: .isResponse) ?? false
        self.targetDeviceId = try container.decodeIfPresent(UUID.self, forKey: .targetDeviceId)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind.rawValue, forKey: .rawKind)
        try container.encodeIfPresent(intentId, forKey: .intentId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(emittedAt, forKey: .emittedAt)
        try container.encode(isResponse, forKey: .isResponse)
        try container.encodeIfPresent(targetDeviceId, forKey: .targetDeviceId)
    }
}

public enum TransportEventDecodeError: Error, Equatable {
    /// Schema-1 encrypted-retry cases `"e"` / `"g"`. Unlock deletes leftover jobs.
    case retiredEncryptedRetry
}

public enum TransportEvent: Sendable, Codable {
    case sessionReestablishment(SessionReestablishmentEnvelope)
    case linkedDeviceReprovisioning(LinkedDeviceReprovisioningBundle)
    case synchronizeOneTimeKeys(SynchronizationKeyIdentities)
    case refreshOneTimeKeys
    /// Peer acknowledges that a published OTK replenish batch is on the server.
    case publishedOneTimeKeysReplenished

    enum CodingKeys: String, CodingKey {
        case sessionReestablishment = "a"
        case linkedDeviceReprovisioning = "b"
        case synchronizeOneTimeKeys = "c"
        case refreshOneTimeKeys = "d"
        case retiredRequestMessageResend = "e"
        case publishedOneTimeKeysReplenished = "f"
        case retiredMessageResendUnavailable = "g"
    }

    /// Synthesized-enum associated-value key. Remaining cases must stay
    /// byte-identical to the v1 goldens; only `"e"` / `"g"` are rejected.
    private enum AssociatedValueKey: String, CodingKey {
        case _0
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if container.contains(.retiredRequestMessageResend)
            || container.contains(.retiredMessageResendUnavailable) {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: TransportEvent.retiredEncryptedRetryMarker
                )
            )
        }
        if container.contains(.sessionReestablishment) {
            let nested = try container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .sessionReestablishment)
            self = .sessionReestablishment(try nested.decode(SessionReestablishmentEnvelope.self, forKey: ._0))
        } else if container.contains(.linkedDeviceReprovisioning) {
            let nested = try container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .linkedDeviceReprovisioning)
            self = .linkedDeviceReprovisioning(
                try nested.decode(LinkedDeviceReprovisioningBundle.self, forKey: ._0))
        } else if container.contains(.synchronizeOneTimeKeys) {
            let nested = try container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .synchronizeOneTimeKeys)
            self = .synchronizeOneTimeKeys(
                try nested.decode(SynchronizationKeyIdentities.self, forKey: ._0))
        } else if container.contains(.refreshOneTimeKeys) {
            self = .refreshOneTimeKeys
        } else if container.contains(.publishedOneTimeKeysReplenished) {
            self = .publishedOneTimeKeysReplenished
        } else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Unrecognised TransportEvent payload"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .sessionReestablishment(let envelope):
            var nested = container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .sessionReestablishment)
            try nested.encode(envelope, forKey: ._0)
        case .linkedDeviceReprovisioning(let bundle):
            var nested = container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .linkedDeviceReprovisioning)
            try nested.encode(bundle, forKey: ._0)
        case .synchronizeOneTimeKeys(let info):
            var nested = container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .synchronizeOneTimeKeys)
            try nested.encode(info, forKey: ._0)
        case .refreshOneTimeKeys:
            _ = container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .refreshOneTimeKeys)
        case .publishedOneTimeKeysReplenished:
            _ = container.nestedContainer(
                keyedBy: AssociatedValueKey.self, forKey: .publishedOneTimeKeysReplenished)
        }
    }

    static let retiredEncryptedRetryMarker = "PQS_RETIRED_ENCRYPTED_RETRY"

    public static func isRetiredEncryptedRetry(_ error: Error) -> Bool {
        String(describing: error).contains(retiredEncryptedRetryMarker)
    }

    /// True when `data` is a BinaryCodable `TransportEvent` whose case is the
    /// retired encrypted-retry pair (`"e"` / `"g"`).
    public static func carriesRetiredEncryptedRetry(_ data: Data) -> Bool {
        do {
            _ = try BinaryDecoder().decode(TransportEvent.self, from: data)
            return false
        } catch {
            return isRetiredEncryptedRetry(error)
        }
    }
}

/// Internal DTO used when servicing authenticated OOB retry. Not a TransportEvent.
public struct ResendRequest: Sendable, Codable {
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

/// Terminal answer to a `ResendRequest`: the responding device has
/// no replayable frame for these ids and never will.
public struct MessageResendUnavailableNotice: Sendable, Codable, Equatable {
    /// Same batch cap as `ResendRequest`, enforced on encode and
    /// decode so a hostile peer cannot clear an unbounded amount of state.
    public static let maxBatchedIds = ResendRequest.maxBatchedIds

    public let respondingDeviceId: UUID
    public let unavailableSharedMessageIds: [String]

    private enum CodingKeys: String, CodingKey {
        case respondingDeviceId = "a"
        case unavailableSharedMessageIds = "b"
    }

    public init(
        unavailableSharedMessageIds: [String],
        respondingDeviceId: UUID
    ) {
        self.unavailableSharedMessageIds = Self.normalizedIds(unavailableSharedMessageIds)
        self.respondingDeviceId = respondingDeviceId
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        respondingDeviceId = try container.decode(UUID.self, forKey: .respondingDeviceId)
        let ids = try container.decode([String].self, forKey: .unavailableSharedMessageIds)
        unavailableSharedMessageIds = Self.normalizedIds(ids)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(respondingDeviceId, forKey: .respondingDeviceId)
        try container.encode(unavailableSharedMessageIds, forKey: .unavailableSharedMessageIds)
    }

    private static func normalizedIds(_ ids: [String]) -> [String] {
        var seen = Set<String>()
        var normalized: [String] = []
        for rawId in ids {
            let id = rawId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !id.isEmpty, !seen.contains(id) else { continue }
            seen.insert(id)
            normalized.append(id)
            if normalized.count == Self.maxBatchedIds {
                break
            }
        }
        return normalized
    }
}
