//
//  AcceptedEnvelopeRecord.swift
//  post-quantum-solace
//
//  Durable transport idempotency for successfully consumed envelopes,
//  including non-persisted nudgeLocal payloads.
//

import Foundation

/// Persisted accepted-envelope ledger row.
public struct AcceptedEnvelopeRecord: Sendable, Equatable, Codable, Hashable {
    public let senderSecretName: String
    public let senderDeviceId: UUID
    public let envelopeMessageId: String
    public let logicalSharedId: String
    public let acceptedAt: Date
    /// SHA-256 of the frame's signed payload. The envelope id rides outside the
    /// signature and a redelivery can mint a new one; the signed bytes cannot
    /// change, so a replay is recognised by this digest when the id differs.
    /// `nil` on rows written before the field existed or by hosts whose schema
    /// does not persist it: those rows match by envelope id only.
    public let frameFingerprint: Data?

    public init(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String,
        logicalSharedId: String,
        acceptedAt: Date = Date(),
        frameFingerprint: Data? = nil
    ) {
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.envelopeMessageId = envelopeMessageId
        self.logicalSharedId = logicalSharedId
        self.acceptedAt = acceptedAt
        self.frameFingerprint = frameFingerprint
    }

    /// Row identity: one row per sender device and envelope id.
    public var storageKey: String {
        "\(senderSecretName)|\(senderDeviceId.uuidString)|\(envelopeMessageId)"
    }

    /// Lookup key for the row's signed payload, when it carries one.
    public var fingerprintStorageKey: String? {
        frameFingerprint.map {
            Self.fingerprintStorageKey(
                senderSecretName: senderSecretName,
                senderDeviceId: senderDeviceId,
                frameFingerprint: $0)
        }
    }

    /// Every key a lookup may match this row by: the envelope key first, then
    /// the fingerprint key for rows that have one.
    public var lookupKeys: [String] {
        [storageKey] + (fingerprintStorageKey.map { [$0] } ?? [])
    }

    /// Fingerprint lookup key, in a namespace (`#fp:`) envelope ids do not use.
    public static func fingerprintStorageKey(
        senderSecretName: String,
        senderDeviceId: UUID,
        frameFingerprint: Data
    ) -> String {
        "\(senderSecretName)|\(senderDeviceId.uuidString)|#fp:\(frameFingerprint.base64EncodedString())"
    }
}
