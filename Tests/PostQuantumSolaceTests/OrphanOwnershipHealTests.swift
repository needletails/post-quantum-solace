//
//  OrphanOwnershipHealTests.swift
//  post-quantum-solace
//
//  TDD for orphan ownership + same-account recovery-session bind (~95% plan).
//

import Foundation
import SessionEvents
import Testing
@testable import PQSSession

@Suite("Orphan ownership heal policies")
struct OrphanOwnershipHealPolicyTests {
    @Test("same-account non-owner defers without servicing")
    func sameAccountNonOwnerDefers() {
        let decision = OrphanResendOwnershipPolicy.decision(
            isSameAccount: true,
            hasRecentOutboundReplay: false,
            hasLocalMessage: false,
            hasOutboundDeviceSendRecord: false)
        #expect(decision == .deferNotContentOwner)
    }

    @Test("same-account MessageRecord owner services")
    func sameAccountMessageRecordOwnerServices() {
        let decision = OrphanResendOwnershipPolicy.decision(
            isSameAccount: true,
            hasRecentOutboundReplay: false,
            hasLocalMessage: false,
            hasOutboundDeviceSendRecord: true)
        #expect(decision == .serviceAsContentOwner)
    }

    @Test("same-account local message owner services")
    func sameAccountLocalMessageOwnerServices() {
        let decision = OrphanResendOwnershipPolicy.decision(
            isSameAccount: true,
            hasRecentOutboundReplay: false,
            hasLocalMessage: true,
            hasOutboundDeviceSendRecord: false)
        #expect(decision == .serviceAsContentOwner)
    }

    @Test("same-account recent non-persistent replay owner services")
    func sameAccountRecentReplayOwnerServices() {
        let decision = OrphanResendOwnershipPolicy.decision(
            isSameAccount: true,
            hasRecentOutboundReplay: true,
            hasLocalMessage: false,
            hasOutboundDeviceSendRecord: false)
        #expect(decision == .serviceAsContentOwner)
    }

    @Test("cross-account without local content continues lookup")
    func crossAccountContinuesLookup() {
        let decision = OrphanResendOwnershipPolicy.decision(
            isSameAccount: false,
            hasRecentOutboundReplay: false,
            hasLocalMessage: false,
            hasOutboundDeviceSendRecord: false)
        #expect(decision == .continueCrossAccountLookup)
    }

    @Test("same-account orphan mark binds outbound to recovery row")
    func sameAccountOrphanBindPrefersRecovery() {
        let decision = OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: true,
            hasLiveOrphanRow: true,
            hasNonOrphanInitialized: true)
        #expect(decision == .preferOrphanRecovery)
    }

    @Test("peer StickyAdvancedRemint prefers non-orphan initialized")
    func peerStickyAdvancedPrefersNonOrphan() {
        let decision = OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: false,
            hasLiveOrphanRow: true,
            hasNonOrphanInitialized: true)
        #expect(decision == .preferNonOrphanInitialized)
    }

    @Test("no orphan mark falls through")
    func noOrphanMarkFallsThrough() {
        let decision = OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: true,
            hasLiveOrphanRow: false,
            hasNonOrphanInitialized: true)
        #expect(decision == .fallThroughBest)
    }

    @Test("after mark and recovery row gone same-account falls through")
    func markAndRecoveryGoneFallsThrough() {
        // Call site passes hasLiveOrphanRow=true while recovery SessionID is still
        // an active row (orphanResendRecoverySessionByPeer). Only when both are
        // gone may selection fall through to poison sole-initialized.
        let decision = OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: true,
            hasLiveOrphanRow: false,
            hasNonOrphanInitialized: true)
        #expect(decision == .fallThroughBest)
    }
}

/// Pre-merge linked-device log checklist (dogfood echo primary ↔ child):
/// 1. Non-owner: `orphanResendDeferredNotContentOwner` (if NACK observed)
/// 2. Owner only: `orphanResend` / `orphanResendRetransport` + MessageRecord=recovery
/// 3. After failed retransport: `orphanReplayPreferredCleared`
/// 4. Next fresh personal sharedId decrypts — not repeated dead preferred maxSkipped
///
/// Covered by OrphanOwnershipHealPolicyTests (this file), StrictOOBRetryTests
/// (OOB `sendOutOfBandResendRequest`), OutboundOrphanSessionSelectionPolicy tests
/// above, and RecentOutboundReplayStoreTests (peek `contains` before `consume`).
@Suite("Orphan ownership heal contracts")
struct OrphanOwnershipHealSourceTests {
    @Test("ownership and outbound selection policies remain callable")
    func ownershipAndOutboundSelectionPoliciesRemainCallable() {
        _ = OrphanResendOwnershipPolicy.decision
        _ = OutboundOrphanSessionSelectionPolicy.decision
        let oob: (any PQSNetworkHost, [String], String, UUID, UUID) async throws -> Void = {
            try await $0.sendOutOfBandResendRequest(
                failedEnvelopeMessageIds: $1,
                to: $2,
                deviceId: $3,
                requestingDeviceId: $4)
        }
        _ = oob
    }

    /// Covered by RecentOutboundReplayStoreTests.availabilityChecksDoNotConsumeReplayCredit.
    @Test("inbound resend peeks recent replay before consuming one credit")
    func inboundResendPeeksBeforeConsumingOneCredit() {
        var store = RecentOutboundReplayStore<String>(ttl: 600, limit: 256, maxReplays: 5)
        let now = Date(timeIntervalSince1970: 1_000)
        store.remember("payload", sharedId: "control", now: now)
        let firstPeek = store.contains(sharedId: "control", now: now)
        let secondPeek = store.contains(sharedId: "control", now: now)
        #expect(firstPeek)
        #expect(secondPeek)
        let replay = store.consume(sharedId: "control", now: now)
        #expect(replay?.message == "payload")
    }
}
