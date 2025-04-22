//
//  FriendshipMetadata.swift
//  needletail-crypto
//
//  Created by Cole M on 9/19/24.
//

import Foundation

//Both parties can updated friendship metadata, but only for themselves
public struct FriendshipMetadata: Sendable, Codable {
    
    public enum State: String, Sendable, Codable {
        case pending = "a"
        case requested = "b"
        case accepted = "c"
        case rejected = "d"
        case rejectedRequest = "e"
        case friendshipRejected = "f"
        case blocked = "g"
        case blockedUser = "h"
        case unblock = "i"
    }
    
    public var myState: State
    public var theirState: State
    public var ourState: State
    
    // Initializer
    public init(
        myState: State = .pending,
        theirState: State = .pending,
        ourState: State = .pending
    ) {
        self.myState = myState
        self.theirState = theirState
        self.ourState = ourState
    }
    
    // Method to send a friend request
    public mutating func synchronizeRequestedState() {
        myState = .requested
        updateOurState()
    }
    
    // Method to accept a friend request
    public mutating func synchronizeAcceptedState() {
        myState = .accepted
        theirState = .accepted
        updateOurState()
    }
    
    // Method to revoking friendship to original state
    public mutating func synchronizePendingState() {
        myState = .pending
        theirState = .pending
        updateOurState()
    }
    
    public mutating func rejectFriendRequest() {
        myState = .rejectedRequest
        theirState = .rejected
        updateOurState()
    }
    
    // Method to block friend
    public mutating func synchronizeBlockState(receivedBlock: Bool) {
        myState = receivedBlock ? .blocked : .blockedUser
        theirState = receivedBlock ? .blockedUser : .blocked
        updateOurState()
    }
    
    // Method to unblock friend. If we unblock we must request friendship again.
    public mutating func unBlockFriend() {
        myState = .pending
        theirState = .pending
        updateOurState()
    }
    
    
    // Method to update ourState based on individual states
    public mutating func updateOurState() {
        if myState == .blocked {
            // If my state is blocked I cannot change out state
        } else if myState == .accepted && theirState == .accepted {
            ourState = .accepted
        } else if myState == .requested && theirState == .pending {
            ourState = .pending
        } else if myState == .rejected && theirState == .rejectedRequest || myState == .rejectedRequest && theirState == .rejected {
            ourState = .friendshipRejected
        } else if myState == .pending && theirState == .pending {
            ourState = .pending // Both parties are pending
        } else if theirState == .blockedUser {
            ourState = .blocked
        } else if myState == .friendshipRejected && theirState == .pending {
            ourState = .friendshipRejected
        } else if myState == .requested && theirState == .requested {
            ourState = .requested
        } else {
            ourState = .pending // Default state if no other conditions are met
        }
    }
    
    /// Switches the states between the requester and the receiver for clarity in the inbound request process.
    ///
    /// The requester sets `myState`, while the receiver's state is represented by `theirState`.
    /// This method ensures that each user's state is correctly assigned to the other,
    /// making it easier to understand the context of the request.
    ///
    /// This method should be called before updating the contact metadata in response to friendship changes.
    public mutating func switchStates() {
        (myState, theirState) = (theirState, myState)
    }
}
