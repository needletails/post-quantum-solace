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

    public init(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String,
        logicalSharedId: String,
        acceptedAt: Date = Date()
    ) {
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.envelopeMessageId = envelopeMessageId
        self.logicalSharedId = logicalSharedId
        self.acceptedAt = acceptedAt
    }

    public var storageKey: String {
        "\(senderSecretName)|\(senderDeviceId.uuidString)|\(envelopeMessageId)"
    }
}
