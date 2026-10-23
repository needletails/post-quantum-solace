//
//  AcceptedEnvelopeLedgerPolicy.swift
//  post-quantum-solace
//
//  Transport idempotency for successfully consumed envelopes, including
//  non-persisted nudgeLocal payloads (dogfood T13).
//

import Foundation
import SessionModels

/// Composite key for a successfully accepted inbound envelope.
public struct AcceptedEnvelopeKey: Hashable, Sendable, Codable {
    public let senderSecretName: String
    public let senderDeviceId: UUID
    public let envelopeMessageId: String
    /// Digest of the frame's signed payload when the caller has the frame
    /// (see `AcceptedEnvelopeRecord.frameFingerprint`); nil for id-only lookups.
    public let frameFingerprint: Data?

    public init(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String,
        frameFingerprint: Data? = nil
    ) {
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.envelopeMessageId = envelopeMessageId
        self.frameFingerprint = frameFingerprint
    }

    public var storageKey: String {
        "\(senderSecretName)|\(senderDeviceId.uuidString)|\(envelopeMessageId)"
    }

    public var fingerprintStorageKey: String? {
        frameFingerprint.map {
            AcceptedEnvelopeRecord.fingerprintStorageKey(
                senderSecretName: senderSecretName,
                senderDeviceId: senderDeviceId,
                frameFingerprint: $0)
        }
    }
}

/// Pure policy for accepted-envelope ledger decisions.
public enum AcceptedEnvelopeLedgerPolicy: Sendable {
    /// Drop before ratchet when this sender/device already had the envelope id
    /// accepted, or the same signed payload under any envelope id. A key without
    /// a fingerprint, and a row persisted without one, match by envelope id only.
    public static func shouldAckAndDrop(
        key: AcceptedEnvelopeKey,
        accepted: Set<String>
    ) -> Bool {
        guard !key.senderSecretName.isEmpty, !key.envelopeMessageId.isEmpty else { return false }
        if accepted.contains(key.storageKey) { return true }
        guard let fingerprintKey = key.fingerprintStorageKey else { return false }
        return accepted.contains(fingerprintKey)
    }

    /// Only successful decrypt + decode + host handling may mark accepted.
    public static func shouldMarkAccepted(
        decryptSucceeded: Bool,
        payloadDecoded: Bool,
        hostHandlingSucceeded: Bool
    ) -> Bool {
        decryptSucceeded && payloadDecoded && hostHandlingSucceeded
    }

    /// Cross-device: same envelope string from another device is independent.
    public static func keysAreIndependent(
        _ a: AcceptedEnvelopeKey,
        _ b: AcceptedEnvelopeKey
    ) -> Bool {
        a.storageKey != b.storageKey
    }

    /// Retention: keep at least spool retention + safety margin.
    public static func isExpired(
        acceptedAt: Date,
        now: Date,
        retention: TimeInterval
    ) -> Bool {
        now.timeIntervalSince(acceptedAt) > retention
    }
}
