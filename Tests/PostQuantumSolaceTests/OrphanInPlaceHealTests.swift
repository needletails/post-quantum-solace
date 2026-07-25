//
//  OrphanInPlaceHealTests.swift
//  post-quantum-solace
//
//  TDD: in-place heal without remove-contact — blankForHeaderExists trap + bounded
//  post-retransport remint, without reviving C3 remint thrash.
//

import Foundation
import Testing
@testable import PQSSession

@Suite("Orphan in-place heal (no contact remove)")
struct OrphanInPlaceHealTests {
    // MARK: - P1: blankForHeaderExists must not remint twin blanks

    @Test("P1: blank for header blocks ensure (no twin mint storm)")
    func p1_blankForHeaderBlocksEnsure() {
        #expect(
            InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(blankForHeaderExists: true)
                == false)
        #expect(
            InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(blankForHeaderExists: false)
                == true)
    }

    // MARK: - P3: after retransport prove-fail, one remint then retransport/terminal

    @Test("P3: retransport → remint once → retransport → exhaustedUnrecoverable")
    func p3_boundedRemintAfterRetransportProveFail() {
        let recovery = UUID()
        var priorRetransportCount = 0
        var remitsAfterProveFail = 0
        var mintCount = 0

        // Settled MessageRecord == recovery (post first orphan encrypt).
        let firstRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: recovery,
            recoverySessionId: recovery,
            initiatingMarkSessionId: recovery,
            markIsStateLess: false,
            priorRetransportCount: priorRetransportCount,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(firstRearm == .retransportAlreadyServiced)
        priorRetransportCount += 1

        let secondRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: recovery,
            recoverySessionId: recovery,
            initiatingMarkSessionId: recovery,
            markIsStateLess: false,
            priorRetransportCount: priorRetransportCount,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(
            secondRearm == .mintFreshAfterRetransportProveFailed,
            "BUG: after retransport prove-fail, expected one escape-hatch remint (new OTK header)")
        mintCount += 1
        remitsAfterProveFail += 1
        let newRecovery = UUID()

        // Post-remint: prior reset to 0 — reminted CT still gets one retransport.
        let thirdRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: newRecovery,
            recoverySessionId: newRecovery,
            initiatingMarkSessionId: newRecovery,
            markIsStateLess: false,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(thirdRearm == .retransportAlreadyServiced)
        priorRetransportCount = 1

        let fourthRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: newRecovery,
            recoverySessionId: newRecovery,
            initiatingMarkSessionId: newRecovery,
            markIsStateLess: false,
            priorRetransportCount: priorRetransportCount,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(
            fourthRearm == .exhaustedUnrecoverable,
            "BUG: after escape remint + retransport prove-fail, must terminalize (not infinite retransport)")
        #expect(mintCount == 1)
    }

    @Test("P3c: prior=0 with remints already used still retransports once")
    func p3c_postRemintFirstRearmStillRetransports() {
        let recovery = UUID()
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: recovery,
            recoverySessionId: recovery,
            initiatingMarkSessionId: recovery,
            markIsStateLess: false,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: 1)
        #expect(decision == .retransportAlreadyServiced)
    }

    @Test("P3b: without prior retransport, settled MessageRecord never remints (C3)")
    func p3b_noRemintBeforeRetransport() {
        let recovery = UUID()
        for _ in 0..<3 {
            let decision = OrphanResendRemintPolicy.decision(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                initiatingMarkSessionId: recovery,
                markIsStateLess: false,
                priorRetransportCount: 0,
                remintsAfterRetransportProveFail: 0)
            #expect(decision == .retransportAlreadyServiced)
            #expect(decision != .exhaustedUnrecoverable)
        }
    }

    // MARK: - P5: escape-first ordering helper

    @Test("P5: needsEscapeRemint helper matches settled prior>=1 remint budget")
    func p5_needsEscapeRemintHelper() {
        let recovery = UUID()
        #expect(
            OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                priorRetransportCount: 1,
                remintsAfterRetransportProveFail: 0))
        #expect(
            !OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                priorRetransportCount: 0,
                remintsAfterRetransportProveFail: 0))
        #expect(
            !OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                priorRetransportCount: 1,
                remintsAfterRetransportProveFail: 1))
        // Unsettled historical MessageRecord must not force wave remint.
        #expect(
            !OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                messageRecordSessionId: UUID(),
                recoverySessionId: recovery,
                priorRetransportCount: 1,
                remintsAfterRetransportProveFail: 0))
    }

    // MARK: - P4: non-regression source contracts

    @Test("P4: blankForHeaderExists gate remains wired; escape is policy remint not bypass")
    func p4_blankForHeaderExistsNotBypassed() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let ratchet = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/TaskProcessor+Ratchet.swift"),
            encoding: .utf8)
        let policy = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/OrphanResendRemintPolicy.swift"),
            encoding: .utf8)
        let slotPolicy = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Task/InboundInitiatingSlotPolicy.swift"),
            encoding: .utf8)

        #expect(ratchet.contains("blankForHeaderExists"))
        #expect(ratchet.contains("inboundInitiatingSlotEnsureSkipped reason=blankForHeaderExists"))
        #expect(ratchet.contains("InboundInitiatingSlotPolicy.shouldEnsureInboundBlank"))
        #expect(slotPolicy.contains("shouldEnsureInboundBlank"))
        #expect(policy.contains("mintFreshAfterRetransportProveFailed"))
        #expect(policy.contains("exhaustedUnrecoverable"))
        #expect(ratchet.contains("mintFreshAfterRetransportProveFailed")
            || ratchet.contains("orphanResendRemintAfterProveFail"))
        #expect(ratchet.contains("exhaustedUnrecoverable"))
        #expect(ratchet.contains("orphanResendHealExhausted")
            || ratchet.contains("markResendUnavailable"))
        #expect(ratchet.contains("demotePriorOrphanMessageRecordSession")
            || ratchet.contains("demoteProveFailedActive"))
        // Escape candidates ordered first; remint stays in the per-id switch (no preflight mint).
        #expect(ratchet.contains("needsEscapeRemintAfterRetransportProveFail"))
        #expect(ratchet.contains("escapeFirst"))
        #expect(ratchet.contains("performOrphanEscapeRemint"))
        #expect(!ratchet.contains("orphanResendWaveEscapeRemint"))
        // MessageRecord owner (not same-account-only) consults priorRetransportCount.
        #expect(ratchet.contains("if hasMessageRecord"))
        #expect(
            ratchet.contains("priorRetransportCount")
                && ratchet.contains("orphanResendOwnerMissingPlaintext"),
            "BUG: owner-without-plaintext path must consult remint counters (dogfood C8E1)")
        // Must not delete the dedupe gate.
        #expect(!ratchet.contains("blankForHeaderExists = false"))
        // Exhausted path must not remint / reset the recovery lane.
        guard let exhaustedRange = ratchet.range(of: "case .exhaustedUnrecoverable") else {
            Issue.record("missing exhaustedUnrecoverable switch case")
            return
        }
        let afterExhausted = String(ratchet[exhaustedRange.lowerBound...])
        let nextCaseOffset = afterExhausted.range(of: "\n                            case .")?.lowerBound
            ?? afterExhausted.index(afterExhausted.startIndex, offsetBy: min(1200, afterExhausted.count))
        let exhaustedBody = String(afterExhausted[..<nextCaseOffset])
        #expect(!exhaustedBody.contains("resetSessionIdentityForFreshSession("))
        #expect(exhaustedBody.contains("unavailableIds.append"))
        #expect(exhaustedBody.contains("markResendUnavailable"))
        #expect(exhaustedBody.contains("orphanResendHealExhausted"))
    }
}
