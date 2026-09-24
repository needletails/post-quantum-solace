//
//  InboundRecoveryStormPolicy.swift
//  post-quantum-solace
//
//  Event-driven gates that stop dogfood recovery storms:
//  same ciphertext archive-deferred thousands of times.
//
//  Exhaustion / pending passes are tokenized by
//  (sender, device, envelopeMessageId, fingerprint) so a fresh orphan
//  fingerprint cannot consume an older archive-only pass (T17).
//

import Foundation

/// Immutable archive-fallback pass token (transport-safe; no timers).
public struct ArchivedInboundFallbackToken: Hashable, Sendable {
    public let senderSecretName: String
    public let senderDeviceId: UUID
    public let envelopeMessageId: String
    public let fingerprint: Data

    public init(
        senderSecretName: String,
        senderDeviceId: UUID,
        envelopeMessageId: String,
        fingerprint: Data
    ) {
        self.senderSecretName = senderSecretName
        self.senderDeviceId = senderDeviceId
        self.envelopeMessageId = envelopeMessageId
        self.fingerprint = fingerprint
    }

    /// Stable map key for pending/exhausted sets.
    public var storageKey: String {
        let fp = fingerprint.base64EncodedString()
        return "\(senderSecretName)|\(senderDeviceId.uuidString)|\(envelopeMessageId)|\(fp)"
    }

    /// Peer-device prefix used when clearing all tokens for a healed peer.
    public var peerKey: String {
        "\(senderSecretName)|\(senderDeviceId.uuidString)"
    }
}

/// Recovery storm gates: one archive fallback per ciphertext token until a heal
/// event or a new inbound fingerprint opens a distinct token.
public enum InboundRecoveryStormPolicy: Sendable {
    /// Whether to enqueue a `.background` archive try-all for this token.
    public static func shouldDeferArchivedFallback(
        token: ArchivedInboundFallbackToken,
        exhausted: Set<String>,
        pendingPass: Set<String>
    ) -> Bool {
        let key = token.storageKey
        return !exhausted.contains(key) && !pendingPass.contains(key)
    }

    /// Whether a `missingOneTimeKey` frame may be terminalized *now*.
    ///
    /// An active-first try-all that fails with archives present inserts the
    /// token and queues a `.background` archive pass before throwing
    /// `preferredError`. Terminalizing at that throw falsely marks content
    /// unrecoverable that the archive pass then decrypts
    /// (`lanePromotedFromArchive` within ~1s; dogfood Sep 19/23). Gate on
    /// the pending set: absent → terminalize; present → wait for the pass
    /// (which removes the token at start and rethrows on failure).
    public static func shouldTerminalizeDeadEpochNow(
        token: ArchivedInboundFallbackToken,
        pendingPass: Set<String>
    ) -> Bool {
        !pendingPass.contains(token.storageKey)
    }

    /// After one completed archive pass, further redeliveries of the *same*
    /// token must not re-walk archives until a heal event.
    public static func exhaustedAfterArchivePassCompleted(
        current: Set<String>,
        token: ArchivedInboundFallbackToken
    ) -> Set<String> {
        var next = current
        next.insert(token.storageKey)
        return next
    }

    /// Token A must never clear token B's pending/exhausted state.
    public static func tokensAreIndependent(
        _ a: ArchivedInboundFallbackToken,
        _ b: ArchivedInboundFallbackToken
    ) -> Bool {
        a.storageKey != b.storageKey
    }
}
