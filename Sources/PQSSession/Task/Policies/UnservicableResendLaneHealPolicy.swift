//
//  UnservicableResendLaneHealPolicy.swift
//  post-quantum-solace
//
//  Lane heal for a resend-request wave the owner cannot service at all.
//
//  A requester NACK proves the pair state for our outbound lane no longer
//  decrypts our frames. When at least one requested id has replayable
//  plaintext, the orphan-resend ladder mints/reuses a recovery lane and the
//  msg0 replay itself re-proves the lane. But when *every* requested id is
//  terminally unavailable (ephemeral control/sync frames the owner never
//  persisted), no replay is queued, no remint runs, and the owner keeps
//  encrypting new traffic on the same diverged ratchet — every future frame
//  dies the same way (dogfood: parent→child personal lane AEAD-failing for
//  6+ hours after `resendUnavailableSentOutOfBand`, preferred 815D30DF
//  rejecting every frame with underlyingCoreCryptoError 503316581).
//
//  Event-driven and bounded:
//  - Trigger: emitting an unavailable notice for a wave with zero queued
//    replays (concrete proof the content path cannot heal the lane).
//  - Bound: skip when the sticky orphan-resend initiating mark already names
//    a live state-less row. That row is a prior heal the requester has not
//    disproven — its retries for old ids do not indict the fresh lane. A
//    second remint requires new evidence: traffic must flow on the new lane
//    (giving the mark row ratchet state) and the requester must NACK again.
//

import Foundation

/// Pure policy for whether an unservicable resend wave must remint the
/// outbound lane toward the requester device.
public enum UnservicableResendLaneHealPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        /// Mint a fresh initiating (state-less) lane toward the requester so
        /// new outbound traffic goes out as msg0 the requester can accept.
        /// The unavailable content stays lost by design; only the lane heals.
        case remintLane
        /// A live state-less initiating mark already exists — a prior heal
        /// awaiting first use. Do not stack another remint on NACK retries.
        case reuseExistingStateLessMark
        /// The wave queued at least one replay, coalesced onto a replay
        /// already in flight, or answered nothing terminal: the msg0 replay
        /// re-proves the lane, no extra heal.
        case noHealNeeded
    }

    /// - Parameters:
    ///   - queuedReplayCount: replays encrypted/retransported this wave.
    ///   - coalescedReplayCount: ids skipped because a replay was already
    ///     serviced within the cooldown window. That msg0 is in flight (or
    ///     just landed) and re-proves the lane itself; reminting over it
    ///     would discard the very lane it is proving. When the cooldown
    ///     expires the next NACK either queues a fresh replay (which heals)
    ///     or goes terminal (which reaches `.remintLane` here).
    ///   - unavailableCount: ids this owner terminally answered unavailable.
    ///   - stateLessInitiatingMarkIsLive: sticky orphan-resend initiating mark
    ///     names a live, state-less (msg0-capable) row for the requester device.
    public static func decision(
        queuedReplayCount: Int,
        coalescedReplayCount: Int,
        unavailableCount: Int,
        stateLessInitiatingMarkIsLive: Bool
    ) -> Decision {
        guard queuedReplayCount == 0,
              coalescedReplayCount == 0,
              unavailableCount > 0
        else {
            return .noHealNeeded
        }
        if stateLessInitiatingMarkIsLive {
            return .reuseExistingStateLessMark
        }
        return .remintLane
    }
}
