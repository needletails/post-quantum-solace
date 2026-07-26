//
//  OrphanResendRemintPolicy.swift
//  post-quantum-solace
//
//  Orphan-resend remint gate. After MessageRecord settles on the recovery
//  SessionID, a peer NACK means that recovery ciphertext already failed to
//  decrypt (typically blankForHeaderExists). Retransporting the identical
//  signed payload cannot clear that trap and cannot change nackFrameFingerprint,
//  so the requester never rearms — escape remint would never run.
//
//  Settled ladder (hard-capped):
//  1. remint budget remaining → one escape remint (new OTK header)
//  2. remint spent + priorRetransportCount == 0 → retransport the reminted CT
//  3. remint spent + priorRetransportCount >= 1 → exhaustedUnrecoverable
//
//  One recovery SessionID per peer-device wave: unrecovered sharedIds re-encrypt on
//  the same ratchet (msg0 then msg1+). Do not mintFresh solely because MessageRecord
//  still names an unrelated historical session.
//

import Foundation

/// Pure policy for whether sender orphan-resend may mint a fresh initiating session.
public enum OrphanResendRemintPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        /// Insert a new initiating (state-less) session and encrypt msg0.
        case mintFresh
        /// Sticky mark still names a state-less row — reuse it (no remint).
        case reuseStateLessMark
        /// Live recovery SessionID for this peer-device wave — continue ratchet
        /// (msg1+) for unrecovered sharedIds; do not mint a competing blank.
        case reuseRecoveryWave
        /// Escape remint already spent; MessageRecord settled on recovery —
        /// retransport the reminted orphan ciphertext once (not another remint).
        case retransportAlreadyServiced
        /// Settled recovery still poisoned — mint once with a new header (new OTK)
        /// so receiver blankForHeaderExists can clear. Hard-capped.
        case mintFreshAfterRetransportProveFailed
        /// Escape remint already spent and a further retransport still cannot prove —
        /// stop servicing this sharedId (emit unavailable). Not another remint/retransport.
        case exhaustedUnrecoverable
    }

    /// Default cap: one escape-hatch remint for settled recovery prove-fail (not C3 thrash).
    public static let defaultMaxRemintsAfterRetransportProveFail = 1

    /// Decide remint vs reuse vs retransport for one `(sharedId, requesterDevice)` replay.
    ///
    /// - Parameters:
    ///   - messageRecordSessionId: `OutboundDeviceSendRecord.sessionIdentityId` for this
    ///     sharedId/device, if any.
    ///   - recoverySessionId: last orphan-resend recovery SessionID for the peer device
    ///     (`orphanResendRecoverySessionByPeer`).
    ///   - initiatingMarkSessionId: sticky initiating mark, if any.
    ///   - markIsStateLess: whether the marked row is still state-less (msg0-capable).
    ///   - recoverySessionIsLiveActive: recovery SessionID names a live active row
    ///     (state-less or advanced) for this peer device.
    ///   - priorRetransportCount: how many times this sharedId was retransported after
    ///     escape remint (0 = first post-escape delivery → retransport reminted CT).
    ///   - remintsAfterRetransportProveFail: escape-hatch mints already used for this id.
    ///   - maxRemintsAfterRetransportProveFail: hard cap (default 1).
    public static func decision(
        messageRecordSessionId: UUID?,
        recoverySessionId: UUID?,
        initiatingMarkSessionId: UUID?,
        markIsStateLess: Bool,
        recoverySessionIsLiveActive: Bool = false,
        priorRetransportCount: Int = 0,
        remintsAfterRetransportProveFail: Int = 0,
        maxRemintsAfterRetransportProveFail: Int = defaultMaxRemintsAfterRetransportProveFail
    ) -> Decision {
        // Settled MessageRecord == recovery: peer NACK is already prove-fail for that
        // CT (identical retransport cannot rearm). Escape remint first while budget
        // remains; then one retransport of the reminted CT; then terminal.
        if let messageRecordSessionId,
           let recoverySessionId,
           messageRecordSessionId == recoverySessionId
        {
            if remintsAfterRetransportProveFail < maxRemintsAfterRetransportProveFail {
                return .mintFreshAfterRetransportProveFailed
            }
            if priorRetransportCount >= 1 {
                return .exhaustedUnrecoverable
            }
            return .retransportAlreadyServiced
        }

        if initiatingMarkSessionId != nil, markIsStateLess {
            return .reuseStateLessMark
        }

        // Wave reuse: live recovery lane continues the ratchet for other sharedIds
        // whose MessageRecord still names a dead historical session.
        if recoverySessionId != nil, recoverySessionIsLiveActive {
            return .reuseRecoveryWave
        }

        return .mintFresh
    }

    /// Escape remint: MessageRecord already settled on the recovery SessionID and the
    /// remint budget remains. Used to order escape candidates ahead of sibling
    /// `reuseRecoveryWave` encrypts so they do not advance a blankForHeaderExists-
    /// poisoned recovery row first.
    public static func needsEscapeRemintAfterRetransportProveFail(
        messageRecordSessionId: UUID?,
        recoverySessionId: UUID?,
        priorRetransportCount: Int,
        remintsAfterRetransportProveFail: Int,
        maxRemintsAfterRetransportProveFail: Int = defaultMaxRemintsAfterRetransportProveFail
    ) -> Bool {
        decision(
            messageRecordSessionId: messageRecordSessionId,
            recoverySessionId: recoverySessionId,
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            priorRetransportCount: priorRetransportCount,
            remintsAfterRetransportProveFail: remintsAfterRetransportProveFail,
            maxRemintsAfterRetransportProveFail: maxRemintsAfterRetransportProveFail
        ) == .mintFreshAfterRetransportProveFailed
    }
}
