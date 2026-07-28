//
//  EnvelopeMessageIdentityPolicy.swift
//  post-quantum-solace
//
//  Strict §4.1: separate logical content identity from the unique
//  MessageID of each encrypted per-device envelope.
//

import Foundation

/// Pure policy for minting and resolving envelope MessageIDs.
public enum EnvelopeMessageIdentityPolicy: Sendable {
    /// Mint a unique envelope MessageID for one encrypt attempt to one device.
    public static func mintEnvelopeMessageId() -> String {
        UUID().uuidString
    }

    /// Legacy dual-read: packets without `logicalMessageId` treat `id` as both.
    public static func resolveLogicalMessageId(
        envelopeMessageId: String,
        logicalMessageId: String?
    ) -> String {
        if let logicalMessageId, !logicalMessageId.isEmpty {
            return logicalMessageId
        }
        return envelopeMessageId
    }

    /// Fan-out invariant: envelopes for distinct devices must be unique.
    public static func fanoutEnvelopesAreDistinct(
        envelopes: [(deviceId: UUID, envelopeMessageId: String)]
    ) -> Bool {
        guard !envelopes.isEmpty else { return false }
        let ids = envelopes.map(\.envelopeMessageId)
        guard ids.allSatisfy({ !$0.isEmpty }) else { return false }
        return Set(ids).count == ids.count
    }

    /// Resend must replace the envelope id while preserving the logical id.
    public static func resendReplacesEnvelope(
        priorEnvelopeMessageId: String,
        newEnvelopeMessageId: String,
        priorLogicalSharedId: String,
        newLogicalSharedId: String
    ) -> Bool {
        priorLogicalSharedId == newLogicalSharedId
            && !newEnvelopeMessageId.isEmpty
            && newEnvelopeMessageId != priorEnvelopeMessageId
    }
}
