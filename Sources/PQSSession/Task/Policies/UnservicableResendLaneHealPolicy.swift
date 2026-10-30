//
//  UnservicableResendLaneHealPolicy.swift
//  post-quantum-solace
//
//  Lane heal for a resend-request wave the owner cannot service at all.
//
//  A requester NACK says the requester could not decrypt a frame. It is not
//  proof that this lane is diverged: the requester may have refused a blank's
//  decrypt, lost the one-time key the lane cites, or NACKed before its archive
//  pass ran, and each of those has its own repair. When at least one requested
//  id has replayable plaintext, the orphan-resend ladder re-encrypts it on the
//  current lane, and a replay NACKed again is the proof that remints. When
//  every requested id is terminally unavailable (ephemeral control/sync frames
//  the owner never persisted), nothing is proven and nothing is minted: the
//  owner answers with the unavailable notice and keeps its lane. Dogfood
//  2026-10-28: minting on such waves archived the lane the requester was
//  mid-sentence on and consumed one of its one-time keys, and two devices
//  reminted toward each other 17 times in 71 minutes. A lane that is truly
//  dead is re-keyed by the requester's `peerRefresh` on `missingOneTimeKey`.
//

import Foundation

/// Pure policy for what an unservicable resend wave does to the outbound lane
/// toward the requester device.
public enum UnservicableResendLaneHealPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        /// Retired: no wave remints a lane. Kept so callers that matched on it
        /// still compile; `decision` never returns it.
        case remintLane
        /// A live state-less initiating mark already exists — a prior heal
        /// awaiting first use — and still covers the requester.
        case reuseExistingStateLessMark
        /// Nothing to heal: a replay in flight proves the lane itself, no id
        /// was terminal, or the wave was all-terminal and proves nothing.
        case noHealNeeded
    }

    /// - Parameters:
    ///   - queuedReplayCount: replays encrypted/retransported this wave.
    ///   - coalescedReplayCount: ids skipped because a replay was already
    ///     serviced within the cooldown window.
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
        return .noHealNeeded
    }
}
