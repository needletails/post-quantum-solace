//
//  FriendshipStateTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 10/19/24.
//

@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels
import Testing

@Suite(.serialized)
struct FriendshipMetadataTests {
    // MARK: - Initial State Tests

    /// Tests that a newly created `FriendshipMetadata` instance has the correct default states.
    ///
    /// Verifies that all three state properties (`myState`, `theirState`, `ourState`) are
    /// initialized to `.pending`, representing a clean slate for the friendship relationship.
    @Test
    func initialState() {
        let friendship = FriendshipMetadata()
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }

    // MARK: - Friend Request Tests

    /// Tests the friend request initiation process using the new `setRequestedState()` method.
    ///
    /// Verifies that calling `setRequestedState()` correctly updates the current user's
    /// state to `.requested` while maintaining the combined state as `.pending` until
    /// the other party responds.
    @Test
    func sendFriendRequest() {
        var friendship = FriendshipMetadata()
        friendship.setRequestedState()

        #expect(friendship.myState == .requested)
        #expect(friendship.ourState == .pending)
    }

    /// Tests the friend request acceptance process using the new `setAcceptedState()` method.
    ///
    /// Verifies that calling `setAcceptedState()` correctly updates both users' states
    /// to `.accepted` and sets the combined state to `.accepted`, representing a
    /// successful friendship establishment.
    @Test
    func acceptFriendRequest() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .requested)
        friendship.setAcceptedState()

        #expect(friendship.myState == .accepted)
        #expect(friendship.theirState == .accepted)
        #expect(friendship.ourState == .accepted)
    }

    /// Tests the friend request rejection process using the new `rejectRequest()` method.
    ///
    /// Verifies that calling `rejectRequest()` correctly updates the states to reflect
    /// that the current user has rejected a friendship request, resulting in a
    /// `.mutuallyRejected` combined state.
    @Test
    func testRejectRequest() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.rejectRequest()

        #expect(friendship.myState == .rejectedByOther)
        #expect(friendship.theirState == .rejected)
        #expect(friendship.ourState == .mutuallyRejected)
    }

    /// Tests the state reset functionality using the new `resetToPendingState()` method.
    ///
    /// Verifies that calling `resetToPendingState()` correctly resets all states to
    /// `.pending`, effectively canceling any pending requests or resetting the
    /// friendship relationship to its initial state.
    @Test
    func testResetToPendingState() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.resetToPendingState()

        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }

    // MARK: - Block/Unblock Tests

    /// Tests the user blocking functionality using the new `setBlockState(isBlocking:)` method.
    ///
    /// Verifies that calling `setBlockState(isBlocking: false)` correctly updates the
    /// states to reflect that the other party is blocking the current user, resulting
    /// in the current user having a `.blockedByOther` state.
    @Test
    func blockUser() {
        var friendship = FriendshipMetadata()
        friendship.setBlockState(isBlocking: false)

        #expect(friendship.myState == .blockedByOther)
        #expect(friendship.theirState == .blocked)
        #expect(friendship.ourState == .pending)
    }

    /// Tests the user unblocking functionality using the new `unblockUser()` method.
    ///
    /// Verifies that calling `unblockUser()` correctly resets all states to `.pending`,
    /// effectively removing the block and allowing the friendship process to begin again.
    @Test
    func testUnblockUser() {
        var friendship = FriendshipMetadata(myState: .blockedByOther, theirState: .blocked)
        friendship.unblockUser()

        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }

    // MARK: - State Management Tests

    /// Tests the user perspective swapping functionality using the new `swapUserPerspectives()` method.
    ///
    /// Verifies that calling `swapUserPerspectives()` correctly exchanges the `myState`
    /// and `theirState` values, which is useful when processing inbound friendship
    /// requests where the roles of requester and receiver need to be inverted.
    @Test
    func testSwapUserPerspectives() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.swapUserPerspectives()

        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .requested)
    }

    /// Tests the combined state calculation logic using the `updateOurState()` method.
    ///
    /// Verifies that the `updateOurState()` method correctly calculates the combined
    /// state based on various combinations of individual user states. This test covers
    /// multiple scenarios including accepted friendships, pending requests, rejected
    /// requests, and mutual requests.
    @Test
    func testUpdateOurState() {
        // Test accepted state
        var friendship = FriendshipMetadata(myState: .accepted, theirState: .accepted)
        friendship.updateOurState()
        #expect(friendship.ourState == .accepted)

        // Test pending state
        friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.updateOurState()
        #expect(friendship.ourState == .pending)

        // Test rejected state
        friendship = FriendshipMetadata(myState: .rejected, theirState: .rejectedByOther)
        friendship.updateOurState()
        #expect(friendship.ourState == .mutuallyRejected)

        // Test both requested state
        friendship = FriendshipMetadata(myState: .requested, theirState: .requested)
        friendship.updateOurState()
        #expect(friendship.ourState == .requested)
    }
}
