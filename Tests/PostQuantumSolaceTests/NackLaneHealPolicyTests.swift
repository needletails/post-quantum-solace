//
//  NackLaneHealPolicyTests.swift
//  post-quantum-solace
//
//  TDD: ControlDeliveryLanePolicy + OrphanReplayRearmPolicy (NACK lane heal).
//

import Foundation
import SessionEvents
import Testing
@testable import PQSSession

@Suite("NACK lane heal policies")
struct NackLaneHealPolicyTests {
    @Test("mint fresh control when preferred failed try-all")
    func mintWhenPreferredFailed() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: false) == true)
    }

    @Test("mint fresh control when preferred was cleared")
    func mintWhenPreferredCleared() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false) == true)
    }

    @Test("do not mint fresh control when preferred healthy")
    func noMintWhenPreferredHealthy() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false) == false)
    }

    @Test("do not mint fresh control when live orphan or recovery")
    func noMintWhenLiveHealLane() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: true) == false)
    }

    @Test("mint only once per continuous try-all failure episode")
    func mintOncePerContinuousFailureEpisode() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: false))
        #expect(
            !ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false))
    }

    @Test("same fingerprint does not rearm (await sender)")
    func sameFingerprintNoRearm() {
        let fp = Data([0x01, 0x02, 0x03])
        #expect(
            OrphanReplayRearmPolicy.shouldRearm(
                priorFingerprint: fp,
                currentFingerprint: fp,
                attempts: 1) == false)
    }

    @Test("different fingerprint rearms once under cap")
    func differentFingerprintRearms() {
        let prior = Data([0x01])
        let current = Data([0x02])
        #expect(
            OrphanReplayRearmPolicy.shouldRearm(
                priorFingerprint: prior,
                currentFingerprint: current,
                attempts: 1) == true)
        #expect(
            OrphanReplayRearmPolicy.shouldRearm(
                priorFingerprint: prior,
                currentFingerprint: current,
                attempts: 3,
                maxSubmissions: 3) == false)
    }

    @Test("zero attempts never rearms (first NACK path)")
    func zeroAttemptsNoRearm() {
        #expect(
            OrphanReplayRearmPolicy.shouldRearm(
                priorFingerprint: nil,
                currentFingerprint: Data([0x01]),
                attempts: 0) == false)
    }

    @Test("same-account recovery row preferred after initiating mark clear")
    func sameAccountRecoverySurvivesMarkClear() {
        // Recovery SessionID still live → bind outbound (not sole poison initialized).
        let decision = OutboundOrphanSessionSelectionPolicy.decision(
            isSameAccount: true,
            hasLiveOrphanRow: true,
            hasNonOrphanInitialized: true)
        #expect(decision == .preferOrphanRecovery)
    }

    @Test("same-account missingOneTimeKey episode forces remint even if answered")
    func sameAccountOTKEpisodeForcesAnsweredRemint() {
        #expect(
            UnansweredInitiatingLanePolicy.shouldForceRemintEvenIfAnswered(
                isSameAccount: true,
                trigger: "missingOneTimeKeyEpisode"))
        #expect(
            !UnansweredInitiatingLanePolicy.shouldForceRemintEvenIfAnswered(
                isSameAccount: false,
                trigger: "missingOneTimeKeyEpisode"))
        #expect(
            !UnansweredInitiatingLanePolicy.shouldForceRemintEvenIfAnswered(
                isSameAccount: true,
                trigger: "peerRefreshRequest"))
    }

    @Test("same-account NACK requires surgical fresh unless orphan/recovery owns heal")
    func sameAccountNackRequiresSurgicalFreshUnlessHealLane() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false))
        #expect(
            !ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: true,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: true))
        #expect(
            !ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: false,
                liveOrphanOrRecovery: false))
    }

    @Test("cross-account proven poison NACK requires surgical fresh")
    func crossAccountPoisonNackRequiresSurgicalFresh() {
        #expect(
            ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: false))
        #expect(
            !ControlDeliveryLanePolicy.shouldRequireSurgicalFreshLane(
                isSameAccount: false,
                forceFreshInitiating: true,
                liveOrphanOrRecovery: true))
    }

    @Test("explicit outbound pin honors heal blanks not poison initialized")
    func explicitOutboundPinHonorsHealNotPoison() {
        // Surgical / orphan remint blank must survive StickyAdvancedRemint.
        #expect(
            ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient(
                isLiveActive: true,
                isStateLess: true,
                isOrphanOrRecoveryLane: false))
        // Advanced recovery row still owns the heal lane.
        #expect(
            ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient(
                isLiveActive: true,
                isStateLess: false,
                isOrphanOrRecoveryLane: true))
        // Queued poison initialized must rebind (same-account orphan ownership).
        #expect(
            !ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient(
                isLiveActive: true,
                isStateLess: false,
                isOrphanOrRecoveryLane: false))
        #expect(
            !ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient(
                isLiveActive: false,
                isStateLess: true,
                isOrphanOrRecoveryLane: false))
    }
}

/// Covered by NackLaneHealPolicyTests (this file), StrictOOBRetryTests (OOB retry),
/// OrphanInPlaceHealTests P1 (blankForHeaderExists), and StrictOOBRetryTests.
@Suite("NACK lane heal contracts")
struct NackLaneHealSourceTests {
    @Test("control mint, prove-fail demote, fingerprint rearm APIs exist")
    func sourceContractsWired() {
        let oob: (any PQSNetworkHost, [String], String, UUID, UUID) async throws -> Void = {
            try await $0.sendOutOfBandResendRequest(
                failedEnvelopeMessageIds: $1,
                to: $2,
                deviceId: $3,
                requestingDeviceId: $4)
        }
        _ = oob
        _ = OrphanReplayRearmPolicy.shouldRearm
        _ = ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient
        _ = UnansweredInitiatingLanePolicy.shouldForceRemintEvenIfAnswered
        _ = InboundInitiatingSlotPolicy.shouldEnsureInboundBlank
        #expect(InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(blankForHeaderExists: true) == false)
    }
}
