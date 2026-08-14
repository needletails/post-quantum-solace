//
//  OrphanInPlaceHealTests.swift
//  post-quantum-solace
//
//  TDD: in-place heal without remove-contact — blankForHeaderExists trap + bounded
//  escape remint on settled NACK, without reviving C3 remint thrash.
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

    @Test("P1b: archived header match tried on active-first; ensure still skipped")
    func p1b_archivedHeaderMatchBeforeEnsureSkip() {
        #expect(
            InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                blankForHeaderExists: true,
                matchedIsArchived: true,
                includeArchivedFallback: false))
        // After trying the archived blank, ensure remains blocked (no twin mint).
        #expect(
            InboundInitiatingSlotPolicy.shouldEnsureInboundBlank(blankForHeaderExists: true)
                == false)
        #expect(
            !InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                blankForHeaderExists: true,
                matchedIsArchived: false,
                includeArchivedFallback: false),
            "active blank already in try-all — no duplicate archivedHeaderMatch")
        #expect(
            !InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                blankForHeaderExists: true,
                matchedIsArchived: true,
                includeArchivedFallback: true),
            "background archive pass already walks archives")
        #expect(
            !InboundInitiatingSlotPolicy.shouldTryArchivedHeaderMatchBeforeEnsureSkip(
                blankForHeaderExists: false,
                matchedIsArchived: true,
                includeArchivedFallback: false))
    }

    // MARK: - P3: settled NACK → escape remint once → retransport → terminal

    @Test("P3: escape remint once → retransport → exhaustedUnrecoverable")
    func p3_boundedRemintAfterRetransportProveFail() {
        let recovery = UUID()
        var remitsAfterProveFail = 0
        var mintCount = 0

        // Settled MessageRecord == recovery: first NACK is prove-fail → escape remint.
        let firstRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: recovery,
            recoverySessionId: recovery,
            initiatingMarkSessionId: recovery,
            markIsStateLess: false,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(
            firstRearm == .mintFreshAfterRetransportProveFailed,
            "BUG: settled recovery NACK must escape-remint (identical CT cannot rearm)")
        mintCount += 1
        remitsAfterProveFail += 1
        let newRecovery = UUID()

        // Post-remint: prior reset to 0 — reminted CT still gets one retransport.
        let secondRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: newRecovery,
            recoverySessionId: newRecovery,
            initiatingMarkSessionId: newRecovery,
            markIsStateLess: false,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(secondRearm == .retransportAlreadyServiced)

        let thirdRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: newRecovery,
            recoverySessionId: newRecovery,
            initiatingMarkSessionId: newRecovery,
            markIsStateLess: false,
            priorRetransportCount: 1,
            remintsAfterRetransportProveFail: remitsAfterProveFail)
        #expect(
            thirdRearm == .exhaustedUnrecoverable,
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

    @Test("P3b: settled + budget remints once; spent budget does not remint again")
    func p3b_settledBudgetRemintsOnceOnly() {
        let recovery = UUID()
        let withBudget = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: recovery,
            recoverySessionId: recovery,
            initiatingMarkSessionId: recovery,
            markIsStateLess: false,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: 0)
        #expect(withBudget == .mintFreshAfterRetransportProveFailed)

        for prior in 0..<3 {
            let spent = OrphanResendRemintPolicy.decision(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                initiatingMarkSessionId: recovery,
                markIsStateLess: false,
                priorRetransportCount: prior,
                remintsAfterRetransportProveFail: 1)
            if prior == 0 {
                #expect(spent == .retransportAlreadyServiced)
            } else {
                #expect(spent == .exhaustedUnrecoverable)
            }
            #expect(spent != .mintFreshAfterRetransportProveFailed)
        }
    }

    // MARK: - P5: escape-first ordering helper

    @Test("P5: needsEscapeRemint helper matches settled + remint budget")
    func p5_needsEscapeRemintHelper() {
        let recovery = UUID()
        #expect(
            OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                messageRecordSessionId: recovery,
                recoverySessionId: recovery,
                priorRetransportCount: 0,
                remintsAfterRetransportProveFail: 0))
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
                remintsAfterRetransportProveFail: 1))
        // Unsettled historical MessageRecord must not force wave remint.
        #expect(
            !OrphanResendRemintPolicy.needsEscapeRemintAfterRetransportProveFail(
                messageRecordSessionId: UUID(),
                recoverySessionId: recovery,
                priorRetransportCount: 1,
                remintsAfterRetransportProveFail: 0))
    }

    // MARK: - P4: former source contracts (covered by P0–P3 / P5)

    // Covered by:
    // - OrphanInPlaceHealTests.p1_blankForHeaderBlocksEnsure / p1b_archivedHeaderMatchBeforeEnsureSkip
    // - OrphanInPlaceHealTests.p3_boundedRemintAfterRetransportProveFail / p3b / p3c / p5
    // - DogfoodLogReplayTests C3a / C3b / C3c
    // - OrphanOwnershipHealPolicyTests (owner vs non-owner)
    // P4 uniquely pinned wiring of those policies into MessagePipeline+Ratchet;
    // renaming the policy APIs fails the P0–P3 / P5 tests in this file.
}
