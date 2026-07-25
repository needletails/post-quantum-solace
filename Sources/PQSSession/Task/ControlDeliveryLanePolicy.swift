//
//  ControlDeliveryLanePolicy.swift
//  post-quantum-solace
//
//  requestMessageResend control must escape a prove-failed preferred lane.
//  Preferred is a post-decrypt hint — never a prison after try-all failure.
//  When orphan/recovery already owns the heal lane, NACK rides that lane (same as
//  unavailable notices) — never demote-all forceFresh.
//

import Foundation

/// Pure policy: whether NACK / resend-request control should attempt a fresh lane escape.
public enum ControlDeliveryLanePolicy: Sendable {
    /// - Parameters:
    ///   - preferredFailedInTryAll: the preferred (or sole try-first) active failed decrypt
    ///     in this undecryptable pass.
    ///   - preferredCleared: preferred pin was cleared for this peer device on this path
    ///     (rearm / prove-fail cleanup).
    ///   - liveOrphanOrRecovery: orphan initiating mark or recovery SessionID is live for
    ///     this peer device — NACK must ride that lane, not mint a competing blank.
    /// - Returns: `true` when control delivery should clear preferred and resolve via
    ///   ride-outbound / surgical insert (not demote-all reset).
    public static func shouldMintFreshControlLane(
        preferredFailedInTryAll: Bool,
        preferredCleared: Bool,
        liveOrphanOrRecovery: Bool = false
    ) -> Bool {
        if liveOrphanOrRecovery {
            return false
        }
        return preferredFailedInTryAll || preferredCleared
    }
}
