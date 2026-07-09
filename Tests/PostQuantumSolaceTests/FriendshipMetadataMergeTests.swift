//
//  FriendshipMetadataMergeTests.swift
//  post-quantum-solace
//

import Foundation
import SessionModels
import Testing
@testable import SessionEvents

@Suite("Friendship metadata merge")
struct FriendshipMetadataMergeTests {

    @Test("inbound accept advances a pending requester")
    func inboundAcceptAdvancesPendingRequester() {
        let stored = FriendshipMetadata(myState: .requested, theirState: .pending, ourState: .pending)
        let inbound = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: inbound,
            stored: stored)
        #expect(resolved.ourState == FriendshipMetadata.State.accepted)
    }

    @Test("inbound request advances a blank recipient")
    func inboundRequestAdvancesBlankRecipient() {
        let stored = FriendshipMetadata()
        let inbound = FriendshipMetadata(myState: .pending, theirState: .requested, ourState: .pending)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: inbound,
            stored: stored)
        #expect(resolved.theirState == FriendshipMetadata.State.requested)
    }

    @Test("stale pending sync does not downgrade an outstanding request")
    func stalePendingSyncDoesNotDowngradeOutstandingRequest() {
        let stored = FriendshipMetadata(myState: .requested, theirState: .pending, ourState: .pending)
        let stale = FriendshipMetadata(myState: .pending, theirState: .pending, ourState: .pending)
        let resolved = FriendshipMetadataConflictPolicy.preferSettled.resolve(
            passed: stale,
            stored: stored)
        #expect(resolved.myState == FriendshipMetadata.State.requested)
    }

    @Test("stale pending sync does not dismiss an accept prompt")
    func stalePendingSyncDoesNotDismissAcceptPrompt() {
        let stored = FriendshipMetadata(myState: .pending, theirState: .requested, ourState: .pending)
        let stale = FriendshipMetadata(myState: .pending, theirState: .pending, ourState: .pending)
        let resolved = FriendshipMetadataConflictPolicy.preferSettled.resolve(
            passed: stale,
            stored: stored)
        #expect(resolved.theirState == FriendshipMetadata.State.requested)
    }

    @Test("inbound friendship cannot override a block this user initiated")
    func inboundFriendshipCannotOverrideSelfInitiatedBlock() {
        let stored = FriendshipMetadata(myState: .blocked, theirState: .blockedByOther, ourState: .blocked)
        let inbound = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: inbound,
            stored: stored)
        #expect(resolved.myState == FriendshipMetadata.State.blocked)
    }

    @Test("symmetric pending reset is honored as explicit peer intent")
    func symmetricPendingResetIsHonoredAsExplicitPeerIntent() {
        let stored = FriendshipMetadata(myState: .requested, theirState: .pending, ourState: .pending)
        let reset = FriendshipMetadata(myState: .pending, theirState: .pending, ourState: .pending)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: reset,
            stored: stored)
        #expect(resolved.myState == FriendshipMetadata.State.pending)
        #expect(resolved.theirState == FriendshipMetadata.State.pending)
    }

    @Test("stale transient replay does not downgrade accepted friendships")
    func staleTransientReplayDoesNotDowngradeAccepted() {
        let stored = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        let stale = FriendshipMetadata(myState: .pending, theirState: .requested, ourState: .pending)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: stale,
            stored: stored)
        #expect(resolved.ourState == FriendshipMetadata.State.accepted)
    }

    @Test("peer block applies over an accepted friendship")
    func peerBlockAppliesOverAcceptedFriendship() {
        let stored = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        // Peer blocked us; after the receiver-side perspective swap the packet
        // arrives as (blockedByOther, blocked).
        let inboundBlock = FriendshipMetadata(myState: .blockedByOther, theirState: .blocked, ourState: .blocked)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: inboundBlock,
            stored: stored)
        #expect(resolved.ourState == FriendshipMetadata.State.blocked)
    }

    @Test("peer rejection applies over an outstanding request")
    func peerRejectionAppliesOverOutstandingRequest() {
        let stored = FriendshipMetadata(myState: .requested, theirState: .pending, ourState: .pending)
        // Peer rejected our request; after the perspective swap the packet
        // arrives as (rejected, rejectedByOther).
        let inboundReject = FriendshipMetadata(myState: .rejected, theirState: .rejectedByOther, ourState: .mutuallyRejected)
        let resolved = FriendshipMetadataConflictPolicy.inboundFriendship.resolve(
            passed: inboundReject,
            stored: stored)
        #expect(resolved.myState == FriendshipMetadata.State.rejected)
    }

    @Test("sibling block sync applies over an accepted friendship")
    func siblingBlockSyncAppliesOverAcceptedFriendship() {
        let stored = FriendshipMetadata(myState: .accepted, theirState: .accepted, ourState: .accepted)
        let siblingBlock = FriendshipMetadata(myState: .blocked, theirState: .blockedByOther, ourState: .blocked)
        let resolved = FriendshipMetadataConflictPolicy.preferSettled.resolve(
            passed: siblingBlock,
            stored: stored)
        #expect(resolved.ourState == FriendshipMetadata.State.blocked)
    }
}
