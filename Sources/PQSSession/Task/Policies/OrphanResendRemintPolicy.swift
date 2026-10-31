//
//  OrphanResendRemintPolicy.swift
//  post-quantum-solace
//
//  Orphan-resend remint gate. A peer NACK says one frame failed, not that its lane
//  is dead. Only a NACK citing a replay's own envelope proves that: that ciphertext
//  already failed to decrypt (typically blankForHeaderExists), and retransporting
//  the identical signed payload cannot clear that trap and cannot change
//  nackFrameFingerprint, so the requester never rearms.
//
//  Proven on the recovery SessionID, the ladder runs (hard-capped):
//  1. remint budget remaining → one escape remint (new OTK header)
//  2. remint spent + priorRetransportCount == 0 → retransport the reminted CT
//  3. remint spent + priorRetransportCount >= 1 → exhaustedUnrecoverable
//
//  Otherwise a replay rides the newest lane the peer has answered, with no mint and
//  no one-time key. With no such lane it takes the sticky state-less mark (msg0 then
//  msg1+ for the whole wave), then the live recovery row, so the frames of one dead
//  lane share one mint. Only a frame on that row itself, or no row at all, mints.
//

import Foundation

/// Pure policy for whether sender orphan-resend may mint a fresh initiating session.
public enum OrphanResendRemintPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        /// Insert a new initiating (state-less) session and encrypt msg0.
        case mintFresh
        /// Sticky mark still names a state-less row — reuse it (no remint).
        case reuseStateLessMark
        /// The peer has answered a live lane — continue that ratchet. Re-encrypting
        /// on an unanswered row would cite the same one-time key again.
        case replayOnAnsweredLane
        /// Live recovery SessionID for this peer device — continue its ratchet (msg1+)
        /// for a frame on another row. Do not mint a competing row.
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
    ///   - citationProvesDeadLane: the request cited the live record's own envelope and that
    ///     envelope is a replay (`resendAttempt > 0`). A logical-id citation resolves to
    ///     the live replay record but never proves it failed.
    ///   - hasAnsweredLane: a live row for this peer device has received frames, not
    ///     counting the row a proven citation names.
    ///   - recoverySessionIsLiveActive: recovery SessionID names a live active row for
    ///     this peer device.
    ///   - priorRetransportCount: how many times this sharedId was retransported after
    ///     escape remint (0 = first post-escape delivery → retransport reminted CT).
    ///   - remintsAfterRetransportProveFail: escape-hatch mints already used for this id.
    ///   - maxRemintsAfterRetransportProveFail: hard cap (default 1).
    public static func decision(
        messageRecordSessionId: UUID?,
        recoverySessionId: UUID?,
        initiatingMarkSessionId: UUID?,
        markIsStateLess: Bool,
        citationProvesDeadLane: Bool = false,
        hasAnsweredLane: Bool = false,
        recoverySessionIsLiveActive: Bool = false,
        priorRetransportCount: Int = 0,
        remintsAfterRetransportProveFail: Int = 0,
        maxRemintsAfterRetransportProveFail: Int = defaultMaxRemintsAfterRetransportProveFail
    ) -> Decision {
        // Proven dead on the recovery lane (identical retransport cannot rearm).
        // Escape remint first while budget remains; then one retransport of the
        // reminted CT; then terminal.
        if citationProvesDeadLane,
           let messageRecordSessionId,
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

        if hasAnsweredLane {
            return .replayOnAnsweredLane
        }

        if initiatingMarkSessionId != nil, markIsStateLess {
            return .reuseStateLessMark
        }

        if recoverySessionIsLiveActive, messageRecordSessionId != recoverySessionId {
            return .reuseRecoveryWave
        }

        return .mintFresh
    }

    /// Escape remint: a proven citation on the recovery SessionID with remint budget
    /// left. Used to order escape candidates ahead of sibling replays so they do not
    /// advance a blankForHeaderExists-poisoned recovery row first.
    public static func needsEscapeRemintAfterRetransportProveFail(
        messageRecordSessionId: UUID?,
        recoverySessionId: UUID?,
        citationProvesDeadLane: Bool,
        priorRetransportCount: Int,
        remintsAfterRetransportProveFail: Int,
        maxRemintsAfterRetransportProveFail: Int = defaultMaxRemintsAfterRetransportProveFail
    ) -> Bool {
        decision(
            messageRecordSessionId: messageRecordSessionId,
            recoverySessionId: recoverySessionId,
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            citationProvesDeadLane: citationProvesDeadLane,
            priorRetransportCount: priorRetransportCount,
            remintsAfterRetransportProveFail: remintsAfterRetransportProveFail,
            maxRemintsAfterRetransportProveFail: maxRemintsAfterRetransportProveFail
        ) == .mintFreshAfterRetransportProveFailed
    }
}
