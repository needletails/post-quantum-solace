//
//  InboundInitiatingSlotPolicy.swift
//  post-quantum-solace
//
//  Inbound blank ensure gate. If a blank for this frame's header
//  (LTK + OTK id) already exists and failed try-all, minting another identical
//  blank cannot PQXDH-succeed and causes ensure storms (dogfood activate-fail
//  cycles). Escape is a *new* orphan recovery header (new OTK), not reminting twins.
//

import Foundation

/// Pure policy: whether inbound decrypt may call `ensureInboundInitiatingSessionIdentity`.
public enum InboundInitiatingSlotPolicy: Sendable {
    /// - Parameter blankForHeaderExists: a state-less (active or archived) row already
    ///   matches this frame's remote LTK + OTK id.
    /// - Returns: `true` only when ensure may mint a new blank for this header.
    public static func shouldEnsureInboundBlank(blankForHeaderExists: Bool) -> Bool {
        !blankForHeaderExists
    }

    /// Active-first does not walk archives, but `blankForHeaderExists` counts archived
    /// blanks. When the header match is archived, try that blank before ensure-skip.
    public static func shouldTryArchivedHeaderMatchBeforeEnsureSkip(
        blankForHeaderExists: Bool,
        matchedIsArchived: Bool,
        includeArchivedFallback: Bool
    ) -> Bool {
        blankForHeaderExists && matchedIsArchived && !includeArchivedFallback
    }
}
