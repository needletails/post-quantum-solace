//
//  FriendshipRequestError.swift
//  post-quantum-solace
//
//  Created by Cole M on 2026-04-17.
//
//  Copyright (c) 2026 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//

import Foundation

/// Errors that ``requestFriendshipStateChange(state:contact:)`` can surface to
/// callers when a state transition is intentionally rejected (as opposed to
/// failing for I/O / cryptographic reasons).
///
/// These previously appeared as silent no-ops, which made the UI feel buggy:
/// a user would tap "Add", nothing would happen, and there was no signal that
/// the request was rejected because (for example) the other party had
/// previously declined. Surfacing a typed error lets the UI display a banner
/// or toast explaining why the action did nothing.
public enum FriendshipRequestError: Error, LocalizedError, Equatable, Sendable {
    /// The relationship is already mutually `.accepted` and the caller asked to
    /// accept again, or to re-send a `.requested`. Treated as a no-op so the
    /// UI doesn't accidentally flip an established friendship.
    case alreadyAccepted

    /// The caller's `myState` is `.rejected`, meaning the other party has
    /// previously declined the friendship. Re-requesting is suppressed so the
    /// rejected user can't repeatedly nudge the rejecter; defensive actions
    /// (block / unblock / cancel) are still allowed and will not throw this.
    case previouslyRejectedByContact

    /// The peer must publish fresh one-time keys and/or the inbound friend request
    /// must be decrypted before accept can bootstrap an outbound reply lane.
    case peerSessionNotReady

    /// The server rejected delivery because this account is on the peer's
    /// `blockedUsers` list (client friendship state may still look unblocked).
    case blockedByPeer

    public var errorDescription: String? {
        switch self {
        case .alreadyAccepted:
            return "You're already friends with this contact."
        case .previouslyRejectedByContact:
            return "This contact previously declined your friend request."
        case .peerSessionNotReady:
            return "Can't accept yet. Wait for the friend request to arrive, then try again."
        case .blockedByPeer:
            return "This contact has blocked you, so the friendship update couldn't be delivered."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .alreadyAccepted:
            return "There's nothing to do — you can already message each other."
        case .previouslyRejectedByContact:
            return "Wait for them to add you, or block this contact if you don't want them to reach you again."
        case .peerSessionNotReady:
            return "Ask them to send the request again while you're both online."
        case .blockedByPeer:
            return "They'll need to unblock you before you can become friends again."
        }
    }
}
