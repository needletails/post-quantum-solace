//
//  SealedOuterCiphertext.swift
//  post-quantum-solace
//
//  Post-quantum sealed-sender outer ciphertext.
//

import DoubleRatchetKit
import Foundation

/// The wire payload for a post-quantum sealed-sender message.
///
/// The ML-KEM ciphertext carries a fresh per-message shared secret. The
/// AES-GCM combined ciphertext contains the nonce, encrypted
/// ``SealedSenderPlaintext``, and authentication tag.
///
/// `recipientKeyId` is a routing hint naming the published recipient ML-KEM
/// public key this box encapsulates to. It is outside the AAD: a tampered
/// hint can only cause a failed lookup, never a wrong accept. Optional so
/// envelopes encoded before the field stay decodeable; `encode(to:)` skips
/// the key entirely when nil so those bytes stay identical.
public struct SealedOuterCiphertext: Sendable, Equatable {
    public let version: UInt8
    public let kemCiphertext: Data
    public let aeadCiphertext: Data
    public let recipientKeyId: UUID?

    enum CodingKeys: String, CodingKey {
        case version = "a"
        case kemCiphertext = "b"
        case aeadCiphertext = "c"
        case recipientKeyId = "d"
    }

    public init(
        version: UInt8,
        kemCiphertext: Data,
        aeadCiphertext: Data,
        recipientKeyId: UUID? = nil
    ) {
        self.version = version
        self.kemCiphertext = kemCiphertext
        self.aeadCiphertext = aeadCiphertext
        self.recipientKeyId = recipientKeyId
    }
}

extension SealedOuterCiphertext: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(UInt8.self, forKey: .version)
        kemCiphertext = try container.decode(Data.self, forKey: .kemCiphertext)
        aeadCiphertext = try container.decode(Data.self, forKey: .aeadCiphertext)
        recipientKeyId = try container.decodeIfPresent(UUID.self, forKey: .recipientKeyId)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(kemCiphertext, forKey: .kemCiphertext)
        try container.encode(aeadCiphertext, forKey: .aeadCiphertext)
        if let recipientKeyId {
            try container.encode(recipientKeyId, forKey: .recipientKeyId)
        }
    }
}

/// Why a sealed inbound envelope could not be opened.
///
/// Key ids are public identifiers of published recipient keys, not secrets.
public enum SealedOpenFailureReason: String, Sendable, Equatable {
    case recipientKeyUnknown
    case authenticationFailed
    case malformed

    /// Classifies an open failure from the optional routing hint, the key ids
    /// this device currently holds, and any `SealedOuterBoxError` thrown by
    /// `open` / `validate`.
    public static func classify(
        hintedKeyId: UUID?,
        heldKeyIds: Set<UUID>,
        boxError: SealedOuterBoxError?
    ) -> SealedOpenFailureReason {
        if let hintedKeyId, !heldKeyIds.contains(hintedKeyId) {
            return .recipientKeyUnknown
        }
        switch boxError {
        case .unsupportedVersion,
             .invalidKEMCiphertextLength,
             .invalidAEADCiphertextLength,
             .invalidRecipientSecretName:
            return .malformed
        default:
            return .authenticationFailed
        }
    }
}

/// Typed failure from `openSealedInbound`. Never used as a sender bounce.
public enum SealedInboundOpenError: Error, Equatable, Sendable {
    case recipientKeyUnknown(keyId: UUID)
    case authenticationFailed
    case malformed(SealedOuterBoxError)

    public var reason: SealedOpenFailureReason {
        switch self {
        case .recipientKeyUnknown:
            return .recipientKeyUnknown
        case .authenticationFailed:
            return .authenticationFailed
        case .malformed:
            return .malformed
        }
    }
}

/// Receiver key selection for `openSealedInbound`.
///
/// Hint present: one matching key, or `recipientKeyUnknown`. Hint absent:
/// current dedicated then final; previous generations only after
/// `authenticationFailed`. Heal stays at the call site.
public enum SealedInboundOpen {
    public static func hintedRecipientKey(
        id: UUID,
        deviceKeys: DeviceKeys
    ) throws -> MLKEMPrivateKey {
        guard let key = deviceKeys.sealedRecipientPrivateKey(matching: id) else {
            throw SealedInboundOpenError.recipientKeyUnknown(keyId: id)
        }
        return key
    }

    public static func currentGenerationKeys(deviceKeys: DeviceKeys) -> [MLKEMPrivateKey] {
        [
            deviceKeys.sealedSenderMLKEMPrivateKey,
            deviceKeys.finalMLKEMPrivateKey
        ].compactMap { $0 }
    }

    public static func previousGenerationKeys(deviceKeys: DeviceKeys) -> [MLKEMPrivateKey] {
        [
            deviceKeys.previousSealedSenderMLKEMPrivateKey,
            deviceKeys.previousFinalMLKEMPrivateKey
        ].compactMap { $0 }
    }

    /// Opens a box with the same key-selection order as `openSealedInbound`.
    public static func open(
        _ ciphertext: SealedOuterCiphertext,
        deviceKeys: DeviceKeys,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        envelopeId: String,
        packetId: String
    ) throws -> SealedSenderPlaintext {
        func open(with key: MLKEMPrivateKey) throws -> SealedSenderPlaintext {
            try SealedOuterBox.open(
                ciphertext,
                recipientFinalMLKEMPrivateKey: key,
                recipientSecretName: recipientSecretName,
                recipientDeviceId: recipientDeviceId,
                envelopeId: envelopeId,
                packetId: packetId
            )
        }
        func mapOpenError(_ error: Error) -> SealedInboundOpenError {
            if let box = error as? SealedOuterBoxError {
                switch SealedOpenFailureReason.classify(
                    hintedKeyId: nil,
                    heldKeyIds: [],
                    boxError: box
                ) {
                case .malformed:
                    return .malformed(box)
                case .recipientKeyUnknown, .authenticationFailed:
                    return .authenticationFailed
                }
            }
            return .authenticationFailed
        }
        func tryKeys(_ keys: [MLKEMPrivateKey]) throws -> SealedSenderPlaintext {
            var last: SealedInboundOpenError = .authenticationFailed
            for key in keys {
                do {
                    return try open(with: key)
                } catch {
                    let mapped = mapOpenError(error)
                    if case .malformed = mapped {
                        throw mapped
                    }
                    last = mapped
                }
            }
            throw last
        }

        if let hintedKeyId = ciphertext.recipientKeyId {
            let key = try hintedRecipientKey(id: hintedKeyId, deviceKeys: deviceKeys)
            do {
                return try open(with: key)
            } catch {
                throw mapOpenError(error)
            }
        }
        do {
            return try tryKeys(currentGenerationKeys(deviceKeys: deviceKeys))
        } catch SealedInboundOpenError.authenticationFailed {
            return try tryKeys(previousGenerationKeys(deviceKeys: deviceKeys))
        }
    }
}

/// Shared `updatedAt` rule for device-signed key bundles.
///
/// `nil` is older than any date. Equal dates keep incoming. Both sides must
/// already have verified the bundle under the device signing key.
public enum DeviceKeyBundleMerge {
    public static func shouldPreferIncoming(
        existingUpdatedAt: Date?,
        incomingUpdatedAt: Date?
    ) -> Bool {
        switch (existingUpdatedAt, incomingUpdatedAt) {
        case (nil, nil):
            return true
        case (nil, .some):
            return true
        case (.some, nil):
            return false
        case let (existing?, incoming?):
            return incoming >= existing
        }
    }
}
