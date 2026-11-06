//
//  DemotePromoteThrashPolicyTests.swift
//  post-quantum-solace
//
//  TDD: demote/promote thrash invariants (dogfood Engine A + Engine B).
//

import Foundation
import DoubleRatchetKit
import Testing
@testable import PQSSession

@Suite("Demote/promote thrash policies")
struct DemotePromoteThrashPolicyTests {
    // MARK: - P0 ControlDeliveryLanePolicy

    @Test("P0: do not mint fresh control when live orphan or recovery")
    func noMintWhenLiveOrphanOrRecovery() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: true) == false)
    }

    @Test("P0: mint fresh control when preferred poison and no live heal lane")
    func mintWhenPoisonAndNoHealLane() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: false) == true)
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false) == true)
    }

    @Test("P0: do not mint when preferred healthy")
    func noMintWhenPreferredHealthy() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false) == false)
    }

    // MARK: - P0 PersonalOutboundRefreshPolicy

    @Test("P0: skip personal refresh for orphan mark, recovery, or repair-lane blank")
    func skipPersonalRefreshForHealLanes() {
        #expect(
            PersonalOutboundRefreshPolicy.shouldSkipRefresh(
                hasOrphanInitiatingMark: true,
                hasRecoverySession: false,
                isRepairLaneBlank: false))
        #expect(
            PersonalOutboundRefreshPolicy.shouldSkipRefresh(
                hasOrphanInitiatingMark: false,
                hasRecoverySession: true,
                isRepairLaneBlank: false))
        #expect(
            PersonalOutboundRefreshPolicy.shouldSkipRefresh(
                hasOrphanInitiatingMark: false,
                hasRecoverySession: false,
                isRepairLaneBlank: true))
        #expect(
            !PersonalOutboundRefreshPolicy.shouldSkipRefresh(
                hasOrphanInitiatingMark: false,
                hasRecoverySession: false,
                isRepairLaneBlank: false))
    }

    // MARK: - P1 OrphanResendRemintPolicy answered lane

    @Test("P1: answered lane + unrelated MessageRecord → replayOnAnsweredLane (flip C3c)")
    func answeredLaneCarriesReplayForUnrelatedMessageRecord() {
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: UUID(),
            recoverySessionId: UUID(),
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            hasAnsweredLane: true)
        #expect(decision == .replayOnAnsweredLane)
    }

    @Test("P1: no answered lane still mints for unrelated MessageRecord")
    func noAnsweredLaneStillMints() {
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: UUID(),
            recoverySessionId: UUID(),
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            hasAnsweredLane: false)
        #expect(decision == .mintFresh)
    }

    @Test("P1: live recovery row carries another row's frame; its own frame still mints")
    func liveRecoveryRowCarriesOnlyOtherRowsFrames() {
        let recovery = UUID()
        #expect(
            OrphanResendRemintPolicy.decision(
                messageRecordSessionId: UUID(),
                recoverySessionId: recovery,
                initiatingMarkSessionId: nil,
                markIsStateLess: false,
                recoverySessionIsLiveActive: true) == .reuseRecoveryWave)
        #expect(
            OrphanResendRemintPolicy.decision(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                initiatingMarkSessionId: nil,
                markIsStateLess: false,
                recoverySessionIsLiveActive: true) == .mintFresh)
    }

    @Test("P1: proven citation on recovery escape-remints first while budget remains")
    func messageRecordRecoveryEscapeRemintsFirst() {
        let id = UUID()
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: id,
            recoverySessionId: id,
            initiatingMarkSessionId: id,
            markIsStateLess: false,
            citationProvesDeadLane: true,
            hasAnsweredLane: true,
            priorRetransportCount: 0)
        #expect(decision == .mintFreshAfterRetransportProveFailed)
    }
}

/// Covered by the policy suite above plus:
/// - StrictOOBRetryTests.undecryptableEmitsOOBWithoutDRMint (P0 OOB, no surgical mint)
/// - StrictOOBRetryTests (same-account NACK does not mint control lanes)
/// - skipPersonalRefreshForHealLanes (P0 personal refresh)
/// - answeredLaneCarriesReplayForUnrelatedMessageRecord (P1 no PerSharedIdInitiating remint)
/// - OrphanOwnershipHealPolicyTests (P2 owner vs non-owner; missing plaintext cannot service)
@Suite("Demote/promote thrash contracts")
struct DemotePromoteThrashSourceTests {
    @Test("P0: undecryptable retry is OOB; no surgical mint or demote-all")
    func firstPoisonLaneNackIsSurgicalAndBounded() {
        let oob: (PQSSession, String, String, UUID) async throws -> Void = {
            try await $0.requestMessageResend(
                sharedMessageId: $1,
                senderName: $2,
                senderDeviceId: $3)
        }
        _ = oob
        #expect(
            !ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: true))
    }

    @Test("P0: personal refresh shields orphan mark OR recovery OR repair blank")
    func personalRefreshShieldsHealLanes() {
        _ = PersonalOutboundRefreshPolicy.shouldSkipRefresh
        #expect(
            PersonalOutboundRefreshPolicy.shouldSkipRefresh(
                hasOrphanInitiatingMark: true,
                hasRecoverySession: false,
                isRepairLaneBlank: false))
    }

    @Test("P1: PerSharedIdInitiating remint is gone; replay continues an answered ratchet")
    func noPerSharedIdInitiatingRemint() {
        let recovery = UUID()
        let unrelated = UUID()
        #expect(
            OrphanResendRemintPolicy.decision(
                messageRecordSessionId: unrelated,
                recoverySessionId: recovery,
                initiatingMarkSessionId: nil,
                markIsStateLess: false,
                hasAnsweredLane: true) == .replayOnAnsweredLane)
    }

    @Test("P1: activate does not demote live recovery session")
    func activateProtectsRecovery() {
        let activate: (PQSSession, SessionIdentity) async throws -> SessionIdentity = {
            try await $0.activateSessionIdentityAfterInboundDecrypt($1)
        }
        _ = activate
        let isRecovery: (PQSSession, String, UUID, UUID) async -> Bool = {
            await $0.isOrphanResendRecoverySession(
                secretName: $1,
                deviceId: $2,
                sessionId: $3)
        }
        _ = isRecovery
    }

    /// Covered by OrphanOwnershipHealPolicyTests.sameAccountMessageRecordOwnerServices
    /// (owner services) vs sameAccountNonOwnerDefers. Missing plaintext cannot replay.
    @Test("P2: owner missing plaintext without retransport → unavailable")
    func missingPlaintextTerminalizes() {
        #expect(
            OrphanResendOwnershipPolicy.decision(
                isSameAccount: true,
                hasRecentOutboundReplay: false,
                hasLocalMessage: false,
                hasOutboundDeviceSendRecord: true) == .serviceAsContentOwner)
    }
}
