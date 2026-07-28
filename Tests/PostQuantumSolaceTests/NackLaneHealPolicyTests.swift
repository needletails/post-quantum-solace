//
//  NackLaneHealPolicyTests.swift
//  post-quantum-solace
//
//  TDD: ControlDeliveryLanePolicy + OrphanReplayRearmPolicy (NACK lane heal).
//

import Foundation
import Testing
@testable import PQSSession

@Suite("NACK lane heal policies")
struct NackLaneHealPolicyTests {
    @Test("mint fresh control when preferred failed try-all")
    func mintWhenPreferredFailed() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: false,
                liveOrphanOrRecovery: false) == true)
    }

    @Test("mint fresh control when preferred was cleared")
    func mintWhenPreferredCleared() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: false,
                preferredCleared: true,
                liveOrphanOrRecovery: false) == true)
    }

    @Test("do not mint fresh control when preferred healthy")
    func noMintWhenPreferredHealthy() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: false,
                preferredCleared: false,
                liveOrphanOrRecovery: false) == false)
    }

    @Test("do not mint fresh control when live orphan or recovery")
    func noMintWhenLiveHealLane() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: true,
                liveOrphanOrRecovery: true) == false)
    }

    @Test("mint only once per continuous try-all failure episode")
    func mintOncePerContinuousFailureEpisode() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: false,
                surgicalEscapeAlreadyAttempted: false,
                liveOrphanOrRecovery: false))
        #expect(
            !ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: false,
                surgicalEscapeAlreadyAttempted: true,
                liveOrphanOrRecovery: false))
        // A cryptographically distinct failed orphan replay earns one bounded remint.
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: true,
                surgicalEscapeAlreadyAttempted: true,
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

@Suite("NACK lane heal source contracts")
struct NackLaneHealSourceTests {
    @Test("control mint, prove-fail demote, fingerprint rearm are wired")
    func sourceContractsWired() throws {
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
        let session = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/PQSSession.swift"),
            encoding: .utf8)
        let events = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/PQSSession+Events.swift"),
            encoding: .utf8)

        // Strict §4.1: retry emission is OOB; surgical lane helpers may remain
        // for legacy decode / other controls during the mixed-fleet window.
        #expect(events.contains("sendOutOfBandResendRequest("))
        #expect(events.contains("resendRequestSubmittedOutOfBand"))
        #expect(sequence.contains("demoteProveFailedActive(")
            || ratchet.contains("proveFailedActiveDemoted")
            || session.contains("proveFailedActiveDemoted"))
        #expect(session.contains("OrphanReplayRearmPolicy.shouldRearm")
            || sequence.contains("OrphanReplayRearmPolicy.shouldRearm"))
        #expect(ratchet.contains("blankForHeaderExists"))
        #expect(!ratchet.contains("blankForHeaderExists = false"))
        // Must NOT seed preference from try-all failure (demote cascade under
        // blankForHeader storms). Preference stays success-only.
        let rolledBack = try #require(ratchet.range(of: "pqs.recovery.laneRolledBack reason="))
        let afterRollback = ratchet[rolledBack.upperBound...]
        let throwPreferred = try #require(afterRollback.range(of: "throw preferredError"))
        let recordWindow = String(afterRollback[..<throwPreferred.lowerBound])
        #expect(!recordWindow.contains("preferredSessionIdentityIdByPeerDevice["))
        #expect(sequence.contains("UnansweredInitiatingLanePolicy.shouldForceRemintEvenIfAnswered"))
        #expect(ratchet.contains("pinnedExplicitOutboundRecipient("))
        #expect(ratchet.contains("ExplicitOutboundRecipientPinPolicy.shouldHonorExplicitRecipient"))
    }
}
