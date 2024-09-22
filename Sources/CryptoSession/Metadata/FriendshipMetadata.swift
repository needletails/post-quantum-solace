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
        case blocked = "e"
        case unblock = "f"
    }
    
    public var myState: State
    public var theirState: State
    public var ourState: State
    
    // Initializer
    init(
        myState: State = .pending,
        theirState: State = .pending,
        ourState: State = .pending
    ) {
        self.myState = myState
        self.theirState = theirState
        self.ourState = ourState
    }
    
    // Method to send a friend request
    mutating func sendFriendRequest() {
        myState = .requested
        updateOurState()
    }
    
    // Method to accept a friend request
    mutating func acceptFriendRequest() {
        myState = .accepted
        updateOurState()
    }
    
    // Method to reject a friend request
    mutating func rejectFriendRequest() {
        myState = .rejected
        updateOurState()
    }
    
    // Method to revoking friendship to original state
    mutating func revokeFriendRequest() {
        myState = .pending
        updateOurState()
    }
    
    // Method to block friend
    mutating func blockFriend() {
        theirState = .blocked
        updateOurState()
    }
    
    // Method to unblock friend
    mutating func unBlockFriend() {
        theirState = .pending
        updateOurState()
    }
    
    
    // Method to update ourState based on individual states
    mutating func updateOurState() {
        if myState == .blocked {
            // If my state is blocked I cannot change out state
        } else if myState == .accepted && theirState == .accepted {
            ourState = .accepted
        } else if myState == .requested && theirState == .pending {
            ourState = .requested
        } else if myState == .rejected || theirState == .rejected {
            ourState = .rejected
        } else if myState == .pending && theirState == .pending {
            ourState = .pending // Both parties are pending
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
    mutating func switchStates() {
        (myState, theirState) = (theirState, myState)
    }
}
