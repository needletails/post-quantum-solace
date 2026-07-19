//
//  OutboundDeviceSendRecord.swift
//  post-quantum-solace
//
//  Per-device outbound encrypt ledger: which local SessionIdentity encrypted a sharedId
//  to a concrete recipient device. Used on resend to detect orphaned sessions.
//

import Foundation

/// Per-recipient-device send ledger entry.
public struct OutboundDeviceSendRecord: Sendable, Equatable, Codable, Hashable {
    public let sharedId: String
    public let recipientSecretName: String
    public let recipientDeviceId: UUID
    /// Local `SessionIdentity.id` used for that encrypt.
    public let sessionIdentityId: UUID
    public let createdAt: Date

    public init(
        sharedId: String,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        sessionIdentityId: UUID,
        createdAt: Date = Date()
    ) {
        self.sharedId = sharedId
        self.recipientSecretName = recipientSecretName
        self.recipientDeviceId = recipientDeviceId
        self.sessionIdentityId = sessionIdentityId
        self.createdAt = createdAt
    }

    public static func key(sharedId: String, recipientDeviceId: UUID) -> String {
        "\(sharedId)|\(recipientDeviceId.uuidString)"
    }
}
