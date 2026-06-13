//
//  FriendshipStateTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-10-19.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
//

@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels
import Testing
import BinaryCodable

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
    /// in the current user having a `.blockedByOther` state and a combined `.blocked` relationship state.
    @Test
    func blockUser() {
        var friendship = FriendshipMetadata()
        friendship.setBlockState(isBlocking: false)

        #expect(friendship.myState == .blockedByOther)
        #expect(friendship.theirState == .blocked)
        #expect(friendship.ourState == .blocked)
    }

    @Test
    func unblockUserRestoresAcceptedFriendship() {
        var friendship = FriendshipMetadata(myState: .accepted, theirState: .accepted)
        friendship.setBlockState(isBlocking: true)
        friendship.unblockUser()

        #expect(friendship.myState == .accepted)
        #expect(friendship.theirState == .accepted)
        #expect(friendship.ourState == .accepted)
        #expect(friendship.blockedPreviousMyState == nil)
        #expect(friendship.blockedPreviousTheirState == nil)
    }

    @Test
    func unblockUserRestoresPriorRequestShape() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.setBlockState(isBlocking: true)
        friendship.unblockUser()

        #expect(friendship.myState == .requested)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }

    @Test
    func unblockUserFallsBackToPendingWithoutPreviousState() {
        var friendship = FriendshipMetadata(myState: .blockedByOther, theirState: .blocked)
        friendship.unblockUser()

        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }

    @Test
    func blockHistorySurvivesBinaryRoundTrip() throws {
        var friendship = FriendshipMetadata(myState: .accepted, theirState: .accepted)
        friendship.setBlockState(isBlocking: true)

        let decoded = try BinaryDecoder().decode(
            FriendshipMetadata.self,
            from: try BinaryEncoder().encode(friendship)
        )

        #expect(decoded.blockedPreviousMyState == .accepted)
        #expect(decoded.blockedPreviousTheirState == .accepted)
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

    // MARK: - Block-state regression tests

    /// Regression test for an `updateOurState()` branch that previously left
    /// `ourState` untouched whenever `myState == .blocked`. This caused the
    /// combined state to lag behind the actual relationship and produced
    /// inconsistent UI any time the inbound pair wasn't the canonical
    /// `(blocked, blockedByOther)` shape.
    @Test
    func updateOurStateMyBlockedNonCanonical() {
        var friendship = FriendshipMetadata(myState: .blocked, theirState: .pending)
        friendship.updateOurState()
        #expect(friendship.ourState == .blocked)

        friendship = FriendshipMetadata(myState: .blocked, theirState: .accepted)
        friendship.updateOurState()
        #expect(friendship.ourState == .blocked)
    }

    /// Symmetric regression test: when an inbound block lands before the local
    /// device records `blockedByOther`, `theirState == .blocked` alone should
    /// still resolve to a combined `.blocked` state.
    @Test
    func updateOurStateTheirBlockedNonCanonical() {
        var friendship = FriendshipMetadata(myState: .pending, theirState: .blocked)
        friendship.updateOurState()
        #expect(friendship.ourState == .blocked)
    }

    // MARK: - Inbound swap-and-recompute regression tests

    /// Mirrors the inbound friendship-state pipeline used by
    /// `NeedleTailPQSSessionDelegate.processMessage` after the fix:
    /// `swapUserPerspectives()` followed by `updateOurState()`. Previously the
    /// receiver instead called `setRequestedState()` after the swap, which
    /// clobbered the swapped `myState` to `.requested` and made the receiver's
    /// UI render "Resend Request" instead of "Be Friends / Reject", so the
    /// friendship could never be agreed upon.
    @Test
    func inboundRequestProducesCorrectReceiverState() {
        var inbound = FriendshipMetadata(myState: .requested, theirState: .pending)
        inbound.swapUserPerspectives()
        inbound.updateOurState()

        #expect(inbound.myState == .pending)
        #expect(inbound.theirState == .requested)
        #expect(inbound.ourState == .pending)
    }

    /// After accepting, the canonical `{accepted, accepted, accepted}` packet
    /// must round-trip cleanly through swap+updateOurState on the requester's
    /// device too.
    @Test
    func inboundAcceptanceProducesAcceptedState() {
        var inbound = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        inbound.swapUserPerspectives()
        inbound.updateOurState()

        #expect(inbound.myState == .accepted)
        #expect(inbound.theirState == .accepted)
        #expect(inbound.ourState == .accepted)
    }

    /// When the rejecter sends `{rejectedByOther, rejected, mutuallyRejected}`,
    /// the receiver should land at `myState=.rejected` (they were the one
    /// rejected) and a combined `.mutuallyRejected` state. Validates that the
    /// post-fix swap+recompute path matches the pre-fix per-state branch for
    /// rejection.
    @Test
    func inboundRejectionProducesMutuallyRejectedState() {
        var inbound = FriendshipMetadata(myState: .rejectedByOther, theirState: .rejected, ourState: .mutuallyRejected)
        inbound.swapUserPerspectives()
        inbound.updateOurState()

        #expect(inbound.myState == .rejected)
        #expect(inbound.theirState == .rejectedByOther)
        #expect(inbound.ourState == .mutuallyRejected)
    }

    /// A blocker sends `{blocked, blockedByOther, blocked}`; the recipient must
    /// see `myState=.blockedByOther` (they were blocked) and a combined
    /// `.blocked` state.
    @Test
    func inboundBlockProducesBlockedByOtherState() {
        var inbound = FriendshipMetadata(myState: .blocked, theirState: .blockedByOther, ourState: .blocked)
        inbound.swapUserPerspectives()
        inbound.updateOurState()

        #expect(inbound.myState == .blockedByOther)
        #expect(inbound.theirState == .blocked)
        #expect(inbound.ourState == .blocked)
    }

    /// After unblocking, a previously accepted relationship should be restored
    /// on the receiver instead of dropping both users into pending.
    @Test
    func inboundUnblockRestoresAcceptedFriendship() {
        var inbound = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        inbound.swapUserPerspectives()
        inbound.updateOurState()

        #expect(inbound.myState == .accepted)
        #expect(inbound.theirState == .accepted)
        #expect(inbound.ourState == .accepted)
    }

    // MARK: - FriendshipRequestError surface

    /// Localized descriptions exist for every typed error so the UI can present
    /// them directly without falling back to the bare error type name.
    @Test
    func friendshipRequestErrorsHaveLocalizedDescriptions() {
        let errors: [FriendshipRequestError] = [
            .alreadyAccepted,
            .previouslyRejectedByContact,
        ]

        for error in errors {
            #expect(error.errorDescription?.isEmpty == false)
            #expect(error.recoverySuggestion?.isEmpty == false)
        }
    }
}
