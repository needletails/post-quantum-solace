//
//  FriendshipMetadata.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/19/24.
//

import Foundation

/// A struct representing the metadata of a friendship between two users.
///
/// This struct manages the friendship state between two parties, allowing both users to update
/// their individual states and maintain a combined state that reflects the overall relationship.
/// The friendship system supports various states including pending requests, accepted friendships,
/// rejections, and blocking functionality.
///
/// ## State Management
/// - `myState`: Represents the current user's perspective of the friendship
/// - `theirState`: Represents the other user's perspective of the friendship  
/// - `ourState`: A computed state that reflects the combined relationship status
///
/// ## Usage Example
/// ```swift
/// var friendship = FriendshipMetadata()
/// friendship.setRequestedState() // Send a friend request
/// friendship.setAcceptedState()  // Accept a friend request
/// friendship.setBlockState(isBlocking: true) // Block the other user
/// ```
public struct FriendshipMetadata: Sendable, Codable {
    
    /// An enumeration representing the various states of a friendship.
    ///
    /// Each state represents a specific point in the friendship lifecycle, from initial
    /// request to final acceptance, rejection, or blocking.
    public enum State: String, Sendable, Codable {
        /// The friendship request is pending - no action has been taken yet.
        case pending = "a"
        
        /// A friendship request has been sent by the current user.
        case requested = "b"
        
        /// The friendship has been accepted by both parties and is active.
        case accepted = "c"
        
        /// The current user has rejected a friendship request from the other party.
        case rejected = "d"
        
        /// The other party has rejected a friendship request from the current user.
        case rejectedByOther = "e"
        
        /// Both parties have rejected each other's friendship requests.
        case mutuallyRejected = "f"
        
        /// The current user has blocked the other party.
        case blocked = "g"
        
        /// The other party has blocked the current user.
        case blockedByOther = "h"
        
        /// The current user has unblocked the other party (resets to pending state).
        case unblocked = "i"
    }
    
    /// The state of the friendship from the current user's perspective.
    ///
    /// This represents how the current user views the friendship relationship.
    public var myState: State
    
    /// The state of the friendship from the other user's perspective.
    ///
    /// This represents how the other user views the friendship relationship.
    public var theirState: State
    
    /// The combined state that reflects the overall friendship status.
    ///
    /// This computed state is derived from both `myState` and `theirState` and represents
    /// the effective status of the friendship relationship.
    public var ourState: State
    
    /// Initializes a new instance of `FriendshipMetadata`.
    ///
    /// Creates a new friendship metadata instance with the specified states. All states
    /// default to `.pending` if not provided.
    ///
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
    
    /// Sets the state to indicate that a friend request has been sent.
    ///
    /// This method updates the current user's state to `.requested` and recalculates
    /// the combined state. Use this when the current user initiates a friendship request.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata()
    /// friendship.setRequestedState()
    /// // friendship.myState == .requested
    /// // friendship.ourState == .pending
    /// ```
    public mutating func setRequestedState() {
        myState = .requested
        updateOurState()
    }
    
    /// Sets the state to indicate that a friend request has been accepted.
    ///
    /// This method updates both users' states to `.accepted` and sets the combined
    /// state to `.accepted`. Use this when both parties have agreed to the friendship.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata(myState: .requested, theirState: .requested)
    /// friendship.setAcceptedState()
    /// // friendship.myState == .accepted
    /// // friendship.theirState == .accepted
    /// // friendship.ourState == .accepted
    /// ```
    public mutating func setAcceptedState() {
        myState = .accepted
        theirState = .accepted
        updateOurState()
    }
    
    /// Resets the friendship states to the original pending state.
    ///
    /// This method clears all friendship states and returns them to the initial
    /// pending state. Useful for canceling requests or resetting the relationship.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
    /// friendship.resetToPendingState()
    /// // friendship.myState == .pending
    /// // friendship.theirState == .pending
    /// // friendship.ourState == .pending
    /// ```
    public mutating func resetToPendingState() {
        myState = .pending
        theirState = .pending
        updateOurState()
    }
    
    /// Sets the state to indicate that a friend request has been rejected.
    ///
    /// This method updates the states to reflect that the current user has rejected
    /// a friendship request from the other party.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata(myState: .pending, theirState: .requested)
    /// friendship.rejectRequest()
    /// // friendship.myState == .rejectedByOther
    /// // friendship.theirState == .rejected
    /// // friendship.ourState == .mutuallyRejected
    /// ```
    public mutating func rejectRequest() {
        myState = .rejectedByOther
        theirState = .rejected
        updateOurState()
    }
    
    /// Sets the block state for the friendship.
    ///
    /// This method updates the states to reflect blocking behavior. When `isBlocking` is `true`,
    /// the current user is blocking the other party. When `false`, the other party is blocking
    /// the current user.
    ///
    /// - Parameter isBlocking: A Boolean indicating whether the current user is blocking the other party.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata()
    /// friendship.setBlockState(isBlocking: true)  // Current user blocks other
    /// // friendship.myState == .blocked
    /// // friendship.theirState == .blockedByOther
    ///
    /// friendship.setBlockState(isBlocking: false) // Other user blocks current user
    /// // friendship.myState == .blockedByOther
    /// // friendship.theirState == .blocked
    /// ```
    public mutating func setBlockState(isBlocking: Bool) {
        myState = isBlocking ? .blocked : .blockedByOther
        theirState = isBlocking ? .blockedByOther : .blocked
        updateOurState()
    }
    
    /// Sets the state to indicate that the user has unblocked the other party.
    ///
    /// This method resets both users' states to `.pending`, effectively removing the block
    /// and allowing the friendship process to begin again.
    ///
    /// ## Important
    /// After unblocking, a new friendship request must be sent to re-establish the relationship.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata(myState: .blocked, theirState: .blockedByOther)
    /// friendship.unblockUser()
    /// // friendship.myState == .pending
    /// // friendship.theirState == .pending
    /// // friendship.ourState == .pending
    /// ```
    public mutating func unblockUser() {
        myState = .pending
        theirState = .pending
        updateOurState()
    }
    
    /// Updates the combined state based on the individual states of both users.
    ///
    /// This method analyzes both `myState` and `theirState` to determine the appropriate
    /// combined state (`ourState`). The logic prioritizes certain states and handles
    /// edge cases in the friendship lifecycle.
    ///
    /// ## State Priority Logic
    /// 1. If current user is blocked, no state changes are allowed
    /// 2. If both users have accepted, the combined state is `.accepted`
    /// 3. If one user has requested and the other is pending, the combined state is `.pending`
    /// 4. If both users have rejected each other, the combined state is `.mutuallyRejected`
    /// 5. If the other user has blocked the current user, the combined state is `.blocked`
    /// 6. Default to `.pending` for any unhandled combinations
    public mutating func updateOurState() {
        if myState == .blocked {
            // If my state is blocked, I cannot change our state.
        } else if myState == .accepted && theirState == .accepted {
            ourState = .accepted
        } else if myState == .requested && theirState == .pending {
            ourState = .pending
        } else if (myState == .rejected && theirState == .rejectedByOther) || (myState == .rejectedByOther && theirState == .rejected) {
            ourState = .mutuallyRejected
        } else if myState == .pending && theirState == .pending {
            ourState = .pending // Both parties are pending.
        } else if theirState == .blockedByOther {
            ourState = .blocked
        } else if myState == .mutuallyRejected && theirState == .pending {
            ourState = .mutuallyRejected
        } else if myState == .requested && theirState == .requested {
            ourState = .requested
        } else {
            ourState = .pending // Default state if no other conditions are met.
        }
    }
    
    /// Switches the states between the requester and the receiver for clarity in the inbound request process.
    ///
    /// This method swaps `myState` and `theirState` to provide a different perspective
    /// on the friendship relationship. This is useful when processing inbound friendship
    /// requests where the roles of requester and receiver need to be inverted.
    ///
    /// ## Use Case
    /// When processing an inbound friendship request, the requester's state becomes `myState`
    /// and the receiver's state becomes `theirState`. This method ensures that each user's
    /// state is correctly assigned to the other, making it easier to understand the context
    /// of the request.
    ///
    /// ## Example
    /// ```swift
    /// var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
    /// friendship.swapUserPerspectives()
    /// // friendship.myState == .pending
    /// // friendship.theirState == .requested
    /// ```
    ///
    /// ## Important
    /// This method should be called before updating the contact metadata in response to
    /// friendship changes to ensure proper state synchronization.
    public mutating func swapUserPerspectives() {
        (myState, theirState) = (theirState, myState)
    }
}

