//
//  PersonalOutboundRefreshPolicy.swift
//  post-quantum-solace
//
//  State-less personal outbound refresh must not demote a live heal lane
//  (orphan initiating, recovery SessionID, or control/repair blank with no OTK).
//

import Foundation

/// Pure policy: whether `prepareStateLessPersonalSessionIdentityForOutbound` may
/// remint via `stateLessPersonalOutboundRefresh`.
public enum PersonalOutboundRefreshPolicy: Sendable {
    /// - Parameters:
    ///   - hasOrphanInitiatingMark: sticky orphan initiating SessionID is set for the device.
    ///   - hasRecoverySession: `orphanResendRecoverySessionByPeer` is set for the device.
    ///   - isRepairLaneBlank: state-less row with no curve OTK (control / repair mint).
    /// - Returns: `true` when remint must be skipped (keep the existing blank).
    public static func shouldSkipRefresh(
        hasOrphanInitiatingMark: Bool,
        hasRecoverySession: Bool,
        isRepairLaneBlank: Bool
    ) -> Bool {
        hasOrphanInitiatingMark || hasRecoverySession || isRepairLaneBlank
    }
}
