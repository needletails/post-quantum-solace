//
//  OrphanOwnershipHealTests.swift
//  post-quantum-solace
//
//  TDD for orphan ownership + same-account recovery-session bind (~95% plan).
//

import Foundation
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
@Suite("Orphan ownership heal source contracts")
struct OrphanOwnershipHealSourceTests {
    @Test("dogfood log checklist audit strings are wired")
    func dogfoodLogChecklistAuditStringsWired() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let ratchet = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        let sequence = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Sequence.swift"),
            encoding: .utf8)
        let events = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/PQSSession+Events.swift"),
            encoding: .utf8)

        #expect(ratchet.contains("orphanResendDeferredNotContentOwner"))
        #expect(ratchet.contains("orphanResendRetransport"))
        #expect(ratchet.contains("feedDeviceScopedControlWrite("))
        #expect(events.contains("sendOutOfBandResendRequest("))
        #expect(sequence.contains("orphanReplayPreferredCleared"))
        #expect(ratchet.contains("OutboundOrphanSessionSelectionPolicy.decision"))
        #expect(ratchet.contains("OrphanResendOwnershipPolicy.decision"))
        #expect(ratchet.contains("orphanResendRecoverySessionId"))
        #expect(ratchet.contains("demotePriorOrphanMessageRecordSession")
            || ratchet.contains("demoteProveFailedActive"))
        #expect(sequence.contains("proveFailedActiveDemoted")
            || ratchet.contains("proveFailedActiveDemoted")
            || sequence.contains("demoteProveFailedActive"))
    }

    @Test("inbound resend peeks recent replay before consuming one credit")
    func inboundResendPeeksBeforeConsumingOneCredit() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let ratchet = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        let processor = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor.swift"),
            encoding: .utf8)
        let store = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/RecentOutboundReplayStore.swift"),
            encoding: .utf8)

        #expect(processor.contains("ttl: 60 * 10"))
        #expect(processor.contains("limit: 256"))
        #expect(processor.contains("maxReplays: 5"))
        #expect(store.contains("func contains("))
        #expect(store.contains("func consume("))
        #expect(ratchet.contains("let hasRecentReplay ="))
        #expect(ratchet.contains("hasRecentOutboundReplay(sharedId:"))
        #expect(ratchet.contains("if let replay = recentOutboundReplayMessage(sharedId:"))
        #expect(ratchet.contains("hasRecentOutboundReplay: hasRecentReplay"))
    }
}
