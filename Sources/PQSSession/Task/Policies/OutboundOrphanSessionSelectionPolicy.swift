//
//  OutboundOrphanSessionSelectionPolicy.swift
//  post-quantum-solace
//
//  When an orphan initiating mark is live beside an initialized active:
//  - same-account (personal/sibling): bind all outbound to the recovery row
//  - cross-account (peer): StickyAdvancedRemint — prefer non-orphan initialized
//

import Foundation

/// Pure policy for `outboundSessionIdentity` when an orphan mark is present.
public enum OutboundOrphanSessionSelectionPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        /// Use the live orphan / recovery SessionIdentity for outbound.
        case preferOrphanRecovery
        /// Peer one-active: do not send on the remint row when another initialized active exists.
        case preferNonOrphanInitialized
        /// Fall through to `bestSessionIdentity`.
        case fallThroughBest
    }

    public static func decision(
        isSameAccount: Bool,
        hasLiveOrphanRow: Bool,
        hasNonOrphanInitialized: Bool
    ) -> Decision {
        guard hasLiveOrphanRow else {
            return .fallThroughBest
        }
        if isSameAccount {
            return .preferOrphanRecovery
        }
        if hasNonOrphanInitialized {
            return .preferNonOrphanInitialized
        }
        return .fallThroughBest
    }
}
