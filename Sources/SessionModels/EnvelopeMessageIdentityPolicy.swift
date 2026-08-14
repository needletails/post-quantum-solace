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
    public static func mintEnvelopeMessageId() -> EnvelopeID {
        EnvelopeID(UUID().uuidString)
    }

    /// Logical id is required; callers must not treat the envelope id as a fallback.
    public static func resolveLogicalMessageId(
        envelopeMessageId: EnvelopeID,
        logicalMessageId: LogicalMessageID
    ) -> LogicalMessageID {
        logicalMessageId
    }

    /// Fan-out invariant: envelopes for distinct devices must be unique.
    public static func fanoutEnvelopesAreDistinct(
        envelopes: [(deviceId: UUID, envelopeMessageId: EnvelopeID)]
    ) -> Bool {
        guard !envelopes.isEmpty else { return false }
        let ids = envelopes.map(\.envelopeMessageId.rawValue)
        guard ids.allSatisfy({ !$0.isEmpty }) else { return false }
        return Set(ids).count == ids.count
    }

    /// Resend must replace the envelope id while preserving the logical id.
    public static func resendReplacesEnvelope(
        priorEnvelopeMessageId: EnvelopeID,
        newEnvelopeMessageId: EnvelopeID,
        priorLogicalSharedId: LogicalMessageID,
        newLogicalSharedId: LogicalMessageID
    ) -> Bool {
        priorLogicalSharedId == newLogicalSharedId
            && !newEnvelopeMessageId.rawValue.isEmpty
            && newEnvelopeMessageId != priorEnvelopeMessageId
    }
}
