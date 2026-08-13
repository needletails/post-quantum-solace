//
//  AcceptedEnvelopeLedgerPolicy.swift
//  post-quantum-solace
//
//  Transport idempotency for successfully consumed envelopes, including
//  non-persisted nudgeLocal payloads (dogfood T13).
//

import Foundation

/// Composite key for a successfully accepted inbound envelope.
public struct AcceptedEnvelopeKey: Hashable, Sendable, Codable {
    public let senderSecretName: String
    public let senderDeviceId: UUID
    public let envelopeMessageId: String

    public init(senderSecretName: String, senderDeviceId: UUID, envelopeMessageId: String) {
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.envelopeMessageId = envelopeMessageId
    }

    public var storageKey: String {
        "\(senderSecretName)|\(senderDeviceId.uuidString)|\(envelopeMessageId)"
    }
}

/// Pure policy for accepted-envelope ledger decisions.
public enum AcceptedEnvelopeLedgerPolicy: Sendable {
    /// Drop before ratchet when the exact sender/device/envelope was accepted.
    public static func shouldAckAndDrop(
        key: AcceptedEnvelopeKey,
        accepted: Set<String>
    ) -> Bool {
        guard !key.senderSecretName.isEmpty, !key.envelopeMessageId.isEmpty else { return false }
        return accepted.contains(key.storageKey)
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
