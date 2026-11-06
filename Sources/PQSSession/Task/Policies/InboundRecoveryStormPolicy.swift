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

import DoubleRatchetKit
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
        exhausted: Set<String>
    ) -> Bool {
        !exhausted.contains(token.storageKey)
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

    /// Terminal error for a failed try-all, decided by who holds the frame's epoch.
    ///
    /// A stateful row on the frame's epoch is the lane the frame belongs to, so its
    /// failure is the class: a chain desync the sender heals by resending, whatever
    /// the other rows said (dogfood 2026-10-28: 23:41:41Z and 01:23:16Z replaced the
    /// batch for a desync the holder failed AEAD on).
    ///
    /// With no holder, a state-less row's `missingOneTimeKey` names the class: PQXDH
    /// ran from the frame's own header, so the header cites a one-time key this
    /// device does not hold, and only a fresh batch (and the peer's refresh) heals
    /// it. No other failure on such a row proves anything about the frame's keys. A
    /// stateful lane's `maxSkippedHeadersExceeded` says nothing about the frame: DRK
    /// throws it after failing to match the header under any of that lane's header
    /// keys, without authenticating anything (child C7420C75 02:10:08Z: the class hid
    /// the blank's `missingOneTimeKey`, and recovery NACKed for ninety seconds before
    /// it replaced the batch).
    ///
    /// Otherwise the preferred lane's error stands. Whichever row's error is chosen,
    /// another lane's `maxSkippedHeadersExceeded` is surfaced over its `expiredKey`,
    /// the resend-owning class.
    static func terminalTryAllError(attempts: [InboundAttemptFailure]) -> Error {
        let holder = attempts.first { $0.holdsFrameEpoch && !$0.stateLess }
        if holder == nil,
           attempts.contains(where: { $0.stateLess && ($0.error as? RatchetError) == .missingOneTimeKey })
        {
            return RatchetError.missingOneTimeKey
        }
        guard let owner = holder ?? attempts.first(where: \.isPreferred) else { return RatchetError.decryptionFailed }
        guard (owner.error as? RatchetError) == .expiredKey,
              attempts.contains(where: { $0.laneId != owner.laneId && ($0.error as? RatchetError) == .maxSkippedHeadersExceeded })
        else { return owner.error }
        return RatchetError.maxSkippedHeadersExceeded
    }
}

/// One lane's failure on a frame, for the rollback audit and the terminal class.
struct InboundAttemptFailure: Sendable {
    let laneId: UUID
    let label: String
    let error: Error
    let stateLess: Bool
    let holdsFrameEpoch: Bool
    let isPreferred: Bool
}

/// The active-first pass missed and queued the archive pass for the frame. The
/// job ends here; the pass re-runs the decrypt and owns the outcome. Nothing is
/// asked of the sender before it has run: a resend request sent now reaches the
/// sender before the pass, and the sender answers it by tearing down the very
/// lane the pass is about to prove (dogfood 2026-10-28: 6DEB4DCE NACKed at
/// 02:10:04Z, decrypted from the archive at 02:10:05Z; the sender had already
/// reminted on the NACK and the next message went out on a lane the receiver
/// could not open).
enum InboundDecryptDeferral: Error {
    case archivePassQueued
}
