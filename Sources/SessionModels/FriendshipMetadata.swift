//
//  FriendshipMetadata.swift
//  needletail-crypto
//
//  Created by Cole M on 9/19/24.
//

import Foundation

/// A struct representing the metadata of a friendship between two users.
///
/// This struct allows both parties to update their friendship states and manage the relationship.
public struct FriendshipMetadata: Sendable, Codable {
    
    /// An enumeration representing the various states of a friendship.
    public enum State: String, Sendable, Codable {
        /// The friendship request is pending.
        case pending = "a"
        
        /// A friendship request has been sent.
        case requested = "b"
        
        /// The friendship has been accepted by both parties.
        case accepted = "c"
        
        /// The friendship has been rejected by one party.
        case rejected = "d"
        
        /// A friendship request has been rejected.
        case rejectedRequest = "e"
        
        /// The friendship has been rejected by the other party.
        case friendshipRejected = "f"
        
        /// The user has blocked the other party.
        case blocked = "g"
        
        /// The other party has been blocked by the user.
        case blockedUser = "h"
        
        /// The user has unblocked the other party.
        case unblock = "i"
    }
    
    /// The state of the friendship for the current user.
    public var myState: State
    
    /// The state of the friendship for the other user.
    public var theirState: State
    
    /// The combined state of the friendship for both users.
    public var ourState: State
    
    /// Initializes a new instance of `FriendshipMetadata`.
    /// - Parameters:
    ///   - myState: The state of the friendship for the current user (default is `.pending`).
    ///   - theirState: The state of the friendship for the other user (default is `.pending`).
    ///   - ourState: The combined state of the friendship (default is `.pending`).
    public init(
        myState: State = .pending,
        theirState: State = .pending,
        ourState: State = .pending
    ) {
        self.myState = myState
        self.theirState = theirState
        self.ourState = ourState
    }
    
    /// Updates the state to indicate that a friend request has been sent.
    public mutating func synchronizeRequestedState() {
        myState = .requested
        updateOurState()
    }
    
    /// Updates the state to indicate that a friend request has been accepted.
    public mutating func synchronizeAcceptedState() {
        myState = .accepted
        theirState = .accepted
        updateOurState()
    }
    
    /// Resets the friendship states to the original pending state.
    public mutating func synchronizePendingState() {
        myState = .pending
        theirState = .pending
        updateOurState()
    }
    
    /// Updates the state to indicate that a friend request has been rejected.
    public mutating func rejectFriendRequest() {
        myState = .rejectedRequest
        theirState = .rejected
        updateOurState()
    }
    
    /// Updates the state to indicate that the user has blocked the other party.
    /// - Parameter receivedBlock: A Boolean indicating whether the user has blocked the other party.
    public mutating func synchronizeBlockState(receivedBlock: Bool) {
        myState = receivedBlock ? .blocked : .blockedUser
        theirState = receivedBlock ? .blockedUser : .blocked
        updateOurState()
    }
    
    /// Updates the state to indicate that the user has unblocked the other party.
    /// If the user unblocks, they must request friendship again.
    public mutating func unBlockFriend() {
        myState = .pending
        theirState = .pending
        updateOurState()
    }
    
    /// Updates the combined state based on the individual states of both users.
    public mutating func updateOurState() {
        if myState == .blocked {
            // If my state is blocked, I cannot change our state.
        } else if myState == .accepted && theirState == .accepted {
            ourState = .accepted
        } else if myState == .requested && theirState == .pending {
            ourState = .pending
        } else if (myState == .rejected && theirState == .rejectedRequest) || (myState == .rejectedRequest && theirState == .rejected) {
            ourState = .friendshipRejected
        } else if myState == .pending && theirState == .pending {
            ourState = .pending // Both parties are pending.
        } else if theirState == .blockedUser {
            ourState = .blocked
        } else if myState == .friendshipRejected && theirState == .pending {
            ourState = .friendshipRejected
        } else if myState == .requested && theirState == .requested {
            ourState = .requested
        } else {
            ourState = .pending // Default state if no other conditions are met.
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

