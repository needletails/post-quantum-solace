//
//  ExplicitOutboundRecipientPinPolicy.swift
//  post-quantum-solace
//
//  Write-path re-resolve may rebind by (secretName, deviceId) via
//  `outboundSessionIdentity`. Explicit `recipientIdentity` must win only for
//  heal / initiating lanes — never for every still-active row (that defeats
//  same-account orphan rebind for queued poison jobs).
//

import Foundation

/// Pure policy: whether `resolveSessionIdentityForOutbound` should honor the
/// task-embedded recipient instead of StickyAdvancedRemint / best-active rebind.
public enum ExplicitOutboundRecipientPinPolicy: Sendable {
    /// - Parameters:
    ///   - isLiveActive: stored row exists and is not inactive-prefixed.
    ///   - isStateLess: ratchet `state == nil` (surgical control, orphan remint,
    ///     outbound-repair blank).
    ///   - isOrphanOrRecoveryLane: embedded id is the live orphan initiating or
    ///     recovery SessionID for that peer device.
    public static func shouldHonorExplicitRecipient(
        isLiveActive: Bool,
        isStateLess: Bool,
        isOrphanOrRecoveryLane: Bool
    ) -> Bool {
        guard isLiveActive else { return false }
        return isStateLess || isOrphanOrRecoveryLane
    }
}
