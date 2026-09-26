//
//  StaleInboundDevicePolicy.swift
//  post-quantum-solace
//
//  Inbound mail from a device id the account directory no longer lists cannot
//  be healed by a resend: the install that encrypted it is gone.
//

import Foundation

/// Pure policy: whether a missing session row is a replaced device, not a mint lag.
enum StaleInboundDevicePolicy: Sendable {
    /// - Parameters:
    ///   - senderDeviceId: Device id on the inbound frame.
    ///   - verifiedDeviceIds: Devices the last directory refresh recorded for that
    ///     account. Empty means the refresh has not written a memo yet.
    /// - Returns: `true` only when the memo is non-empty and excludes this device.
    ///   An empty memo keeps the resend path so a cold start cannot drop a
    ///   device that is still linked.
    static func shouldDrop(
        senderDeviceId: UUID,
        verifiedDeviceIds: Set<UUID>
    ) -> Bool {
        !verifiedDeviceIds.isEmpty && !verifiedDeviceIds.contains(senderDeviceId)
    }
}
