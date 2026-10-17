//
//  StaleInboundDevicePolicy.swift
//  post-quantum-solace
//
//  Inbound mail from a device id the account directory no longer lists cannot
//  be healed by a resend: the install that encrypted it is gone. That verdict
//  needs a live directory answer; a host lookup cache can lag a just-linked
//  device by minutes and would otherwise purge its first messages.
//

import Foundation

/// Pure policy: whether a missing session row is a replaced device, not a mint lag.
enum StaleInboundDevicePolicy: Sendable {
    /// - Parameters:
    ///   - senderDeviceId: Device id on the inbound frame.
    ///   - verifiedDeviceIds: Devices the last directory refresh recorded for that
    ///     account. Empty means the refresh has not written a memo yet.
    ///   - source: Where that memo came from. Only a live lookup can prove a device
    ///     is gone; a cached or offline-rehydrated memo keeps the resend path.
    /// - Returns: `true` only when the memo is live, non-empty, and excludes this
    ///   device. An empty memo keeps the resend path so a cold start cannot drop a
    ///   device that is still linked.
    static func shouldDrop(
        senderDeviceId: UUID,
        verifiedDeviceIds: Set<UUID>,
        source: PQSSession.VerifiedDeviceIdsSource
    ) -> Bool {
        source == .live
            && !verifiedDeviceIds.isEmpty
            && !verifiedDeviceIds.contains(senderDeviceId)
    }
}
