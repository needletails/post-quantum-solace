//
//  DemotePromoteThrashPolicyTests.swift
//  post-quantum-solace
//
//  TDD: demote/promote thrash invariants (dogfood Engine A + Engine B).
//

import Foundation
import Testing
@testable import PQSSession

@Suite("Demote/promote thrash policies")
struct DemotePromoteThrashPolicyTests {
    // MARK: - P0 ControlDeliveryLanePolicy

    @Test("P0: do not mint fresh control when live orphan or recovery")
    func noMintWhenLiveOrphanOrRecovery() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: true,
                liveOrphanOrRecovery: true) == false)
    }

    @Test("P0: mint fresh control when preferred poison and no live heal lane")
    func mintWhenPoisonAndNoHealLane() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: true,
                preferredCleared: false,
                liveOrphanOrRecovery: false) == true)
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: false,
                preferredCleared: true,
                liveOrphanOrRecovery: false) == true)
    }

    @Test("P0: do not mint when preferred healthy")
    func noMintWhenPreferredHealthy() {
        #expect(
            ControlDeliveryLanePolicy.shouldMintFreshControlLane(
                preferredFailedInTryAll: false,
                preferredCleared: false,
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

    // MARK: - P1 OrphanResendRemintPolicy wave reuse

    @Test("P1: live recovery + unrelated MessageRecord → reuseRecoveryWave (flip C3c)")
    func liveRecoveryReusesWaveForUnrelatedMessageRecord() {
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: UUID(),
            recoverySessionId: UUID(),
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            recoverySessionIsLiveActive: true)
        #expect(decision == .reuseRecoveryWave)
    }

    @Test("P1: no live recovery still mints for unrelated MessageRecord")
    func noLiveRecoveryStillMints() {
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: UUID(),
            recoverySessionId: UUID(),
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            recoverySessionIsLiveActive: false)
        #expect(decision == .mintFresh)
    }

    @Test("P1: MessageRecord==recovery still retransports first")
    func messageRecordRecoveryStillRetransports() {
        let id = UUID()
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: id,
            recoverySessionId: id,
            initiatingMarkSessionId: id,
            markIsStateLess: false,
            recoverySessionIsLiveActive: true,
            priorRetransportCount: 0)
        #expect(decision == .retransportAlreadyServiced)
    }
}

@Suite("Demote/promote thrash source contracts")
struct DemotePromoteThrashSourceTests {
    private func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    @Test("P0: NACK rides outbound; no demote-all forceFresh; no priorSubmissions==0 force")
    func nackRidesOutboundNoDemoteAll() throws {
        let root = packageRoot()
        let ratchet = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        let sequence = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Sequence.swift"),
            encoding: .utf8)

        let controlBody = try functionBody(
            named: "func resolveControlDeliverySessionIdentity",
            in: ratchet)
        // Ride outbound even on forceFresh escape; demote-all reset is not the default.
        #expect(controlBody.contains("outboundSessionIdentity("))
        #expect(
            controlBody.contains("demotePriorActives: false")
                || controlBody.contains("preserveExistingActives")
                || controlBody.contains("surgicalControlInsert")
                || controlBody.contains("insertStateLessControlLane"),
            "BUG: forceFresh still uses demote-all reset without surgical insert")
        #expect(!sequence.contains("preferredFailedInTryAll || priorSubmissions == 0"))
        #expect(sequence.contains("liveOrphanOrRecovery"))
    }

    @Test("P0: personal refresh shields orphan mark OR recovery OR repair blank")
    func personalRefreshShieldsHealLanes() throws {
        let ratchet = try String(
            contentsOf: packageRoot().appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        let body = try functionBody(
            named: "private func prepareStateLessPersonalSessionIdentityForOutbound",
            in: ratchet)
        #expect(body.contains("PersonalOutboundRefreshPolicy.shouldSkipRefresh"))
        #expect(body.contains("orphanResendRecoverySessionId("))
    }

    @Test("P1: mid-wave PerSharedIdInitiating remint is gone; wave continues ratchet")
    func noPerSharedIdInitiatingRemint() throws {
        let ratchet = try String(
            contentsOf: packageRoot().appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        #expect(!ratchet.contains("orphanResendPerSharedIdInitiating"))
        #expect(ratchet.contains("reuseRecoveryWave")
            || ratchet.contains("recoverySessionIsLiveActive"))
    }

    @Test("P1: activate does not demote live recovery session")
    func activateProtectsRecovery() throws {
        let identity = try String(
            contentsOf: packageRoot().appendingPathComponent(
                "Sources/PQSSession/PQSSession+SessionIdentity.swift"),
            encoding: .utf8)
        let activateBody = try functionBody(
            named: "internal func activateSessionIdentityAfterInboundDecrypt",
            in: identity)
        #expect(activateBody.contains("isOrphanResendRecoverySession("))
        #expect(
            activateBody.contains("continue")
                || activateBody.contains("skipDemoteRecovery"),
            "BUG: activate still demotes recovery siblings without skip")
    }

    @Test("P2: owner missing plaintext without retransport → unavailable")
    func missingPlaintextTerminalizes() throws {
        let ratchet = try String(
            contentsOf: packageRoot().appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        #expect(ratchet.contains("orphanResendOwnerMissingPlaintext"))
        // After the audit log, path must append unavailableIds / markResendUnavailable
        // (not only continue).
        guard let range = ratchet.range(of: "orphanResendOwnerMissingPlaintext") else {
            Issue.record("missing orphanResendOwnerMissingPlaintext audit")
            return
        }
        let after = String(ratchet[range.upperBound...].prefix(400))
        #expect(
            after.contains("unavailableIds.append")
                || after.contains("markResendUnavailable"),
            "BUG: owner missing plaintext only continues without terminal unavailable")
    }

    private func functionBody(named: String, in source: String) throws -> String {
        guard let start = source.range(of: named) else {
            throw NSError(
                domain: "DemotePromoteThrashSourceTests",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing \(named)"])
        }
        var depth = 0
        var begun = false
        var endIndex = start.upperBound
        var idx = start.upperBound
        while idx < source.endIndex {
            let ch = source[idx]
            if ch == "{" {
                depth += 1
                begun = true
            } else if ch == "}" {
                depth -= 1
                if begun && depth == 0 {
                    endIndex = source.index(after: idx)
                    break
                }
            }
            idx = source.index(after: idx)
        }
        return String(source[start.lowerBound..<endIndex])
    }
}
