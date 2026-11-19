//
//  LateAcceptAfterFailureTests.swift
//  post-quantum-solace
//
//  A message fails with `serverAcceptExhausted` when the accept for one of its envelopes did
//  not arrive within the budget. The envelope stays tracked, so the accept can still arrive
//  (it was queued behind a backlog, or the server answered a later copy). That accept is the
//  server saying it has the message: the message must leave `failed`.
//
//  Real pieces and doubles as in OutboundFailureOverReceiptTests. The accept is delivered
//  through the call nudge-kit makes for a `privateMessageAccepted` frame.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    @Test("A server accept that arrives after the accept budget ran out clears the failure")
    func lateAcceptAfterExhaustionClearsTheFailure() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await exhaustAcceptBudget(rig, for: [pending])
        let failed = try await rowState(rig)
        try #require(failed == .failed("serverAcceptExhausted"), "setup: the message failed for lack of the accept")
        try #require(await alice.isAwaitingServerAccept(pending), "setup: the envelope is still tracked")

        await alice.confirmServerAcceptedEnvelope(pending)

        let observed = try await rowState(rig)
        #expect(observed == .waitingDelivery, "the server accepted the message, it must not stay failed: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("A late accept for one device leaves the failure while another device's accept is missing")
    func lateAcceptForOneDeviceKeepsTheFailureWhileAnotherIsMissing() async throws {
        let rig = try await startAcceptRig(bobChild: true)
        let alice = rig.pair.alice
        let bobMaster = try await envelope(rig, "bob", rig.bobMaster)
        let bobChild = try await envelope(rig, "bob", rig.bobChild)
        try await exhaustAcceptBudget(rig, for: [bobMaster, bobChild])
        let failed = try await rowState(rig)
        try #require(failed == .failed("serverAcceptExhausted"), "setup: the message failed for lack of the accepts")

        await alice.confirmServerAcceptedEnvelope(bobMaster)
        let afterFirst = try await rowState(rig)
        #expect(afterFirst == .failed("serverAcceptExhausted"), "one device's copy is still unaccepted: observed \(String(describing: afterFirst))")

        await alice.confirmServerAcceptedEnvelope(bobChild)
        let afterBoth = try await rowState(rig)
        #expect(afterBoth == .waitingDelivery, "every copy was accepted: observed \(String(describing: afterBoth))")
        await finishRig(rig)
    }

    @Test("Control: a late accept leaves a read receipt applied over the failure")
    func lateAcceptAfterExhaustionKeepsARead() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await deliverToBobMaster(rig)
        try await exhaustAcceptBudget(rig, for: [pending])
        try await hostAppliesReceipt(rig, .read)

        await alice.confirmServerAcceptedEnvelope(pending)

        let observed = try await rowState(rig)
        #expect(observed == .read, "observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("Control: a late accept leaves a failure with another reason")
    func lateAcceptLeavesAFailureWithAnotherReason() async throws {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await exhaustAcceptBudget(rig, for: [pending])
        try await hostAppliesReceipt(rig, .failed("hostReason"))

        await alice.confirmServerAcceptedEnvelope(pending)

        let observed = try await rowState(rig)
        #expect(observed == .failed("hostReason"), "observed \(String(describing: observed))")
        await finishRig(rig)
    }
}
