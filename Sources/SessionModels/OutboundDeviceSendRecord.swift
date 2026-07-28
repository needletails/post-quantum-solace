//
//  OutboundDeviceSendRecord.swift
//  post-quantum-solace
//
//  §4.1 MessageRecord-lite: which local SessionIdentity encrypted a
//  specific envelope to a concrete recipient device. Indexed by envelope
//  MessageID; logical sharedId points at plaintext / chat row.
//

import Foundation

/// Per-recipient-device envelope send ledger entry.
public struct OutboundDeviceSendRecord: Sendable, Equatable, Codable, Hashable {
    /// envelope MessageID for this encrypted send (unique per device encrypt).
    public let envelopeMessageId: String
    /// Logical / application shared id (stable across resends).
    public let sharedId: String
    public let recipientSecretName: String
    public let recipientDeviceId: UUID
    /// Local `SessionIdentity.id` used for that encrypt.
    public let sessionIdentityId: UUID
    public let resendAttempt: Int
    public let createdAt: Date
    /// Set when a later resend supersedes this envelope.
    public let supersededAt: Date?

    public init(
        envelopeMessageId: String,
        sharedId: String,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        sessionIdentityId: UUID,
        resendAttempt: Int = 0,
        createdAt: Date = Date(),
        supersededAt: Date? = nil
    ) {
        self.envelopeMessageId = envelopeMessageId
        self.sharedId = sharedId
        self.recipientSecretName = recipientSecretName
        self.recipientDeviceId = recipientDeviceId
        self.sessionIdentityId = sessionIdentityId
        self.resendAttempt = resendAttempt
        self.createdAt = createdAt
        self.supersededAt = supersededAt
    }

    /// Legacy convenience: backfill treats sharedId as the envelope id.
    public init(
        sharedId: String,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        sessionIdentityId: UUID,
        createdAt: Date = Date()
    ) {
        self.init(
            envelopeMessageId: sharedId,
            sharedId: sharedId,
            recipientSecretName: recipientSecretName,
            recipientDeviceId: recipientDeviceId,
            sessionIdentityId: sessionIdentityId,
            resendAttempt: 0,
            createdAt: createdAt,
            supersededAt: nil)
    }

    public static func key(envelopeMessageId: String) -> String {
        envelopeMessageId
    }

    public static func logicalKey(sharedId: String, recipientDeviceId: UUID) -> String {
        "\(sharedId)|\(recipientDeviceId.uuidString)"
    }

    /// Legacy key retained for dual-read callers during migration.
    public static func key(sharedId: String, recipientDeviceId: UUID) -> String {
        logicalKey(sharedId: sharedId, recipientDeviceId: recipientDeviceId)
    }
}
