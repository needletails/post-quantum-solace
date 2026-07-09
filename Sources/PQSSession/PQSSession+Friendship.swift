//
//  PQSSession+Friendship.swift
//  post-quantum-solace
//
//  Copyright (c) 2026 NeedleTails Organization.
//

import Foundation

public extension PQSSession {
    /// Records that an inbound friendship control packet was decrypted and applied for a peer.
    func markPeerInboundFriendshipConfirmed(_ secretName: String) {
        peerInboundFriendshipConfirmedPeers.insert(secretName)
        logger.log(
            level: .info,
            message: "markPeerInboundFriendshipConfirmed: inbound friendship handshake confirmed for \(secretName)")
    }

    /// True when accept bootstrap may run: inbound friendship was confirmed this session or a
    /// live inbound ratchet row exists (persisted proof a prior decrypt succeeded).
    func peerCanAcceptFriendship(_ secretName: String) async throws -> Bool {
        if peerInboundFriendshipConfirmedPeers.contains(secretName) {
            return true
        }
        guard let peerDevice = try await peerMasterDevice(for: secretName) else {
            return false
        }
        return await hasActiveInboundSessionIdentity(
            secretName: secretName,
            deviceId: peerDevice.deviceId)
    }
}
