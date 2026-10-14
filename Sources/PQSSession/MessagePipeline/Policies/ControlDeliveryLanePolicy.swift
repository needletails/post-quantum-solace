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

/// Pure policy: whether recovery control must mint a surgical fresh lane.
public enum ControlDeliveryLanePolicy: Sendable {
    /// Same-account control must not "ride" an existing outbound match: poison
    /// actives still encrypt locally, so NACKs leave the device (`resendRequestTransported`)
    /// but never decrypt on the sibling (`resendRequestReceived` absent). Surgical
    /// mint with `demotePriorActives: false` — never demote-all, never preference-on-fail.
    /// When orphan/recovery already owns the heal lane, ride that lane instead.
    public static func shouldRequireSurgicalFreshLane(
        isSameAccount: Bool,
        forceFreshInitiating: Bool,
        liveOrphanOrRecovery: Bool
    ) -> Bool {
        if liveOrphanOrRecovery {
            return false
        }
        // Same-account always needs surgical delivery. Cross-account needs the same
        // escape when try-all proved its current outbound match cannot carry recovery
        // control; merely clearing the preferred pin can still select that poison active.
        return isSameAccount || forceFreshInitiating
    }
}
