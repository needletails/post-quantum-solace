//
//  ServerAcceptLedgerReentrancyTests.swift
//  post-quantum-solace
//
//  Every path that resends from the accept ledger awaits the transport, and the ledger is
//  actor state, so other ledger calls run while that send is in flight. A server accept
//  handled meanwhile removes the envelope: the resend must not put it back, or the
//  accepted message is resent, the host is asked to recycle the socket, and in the end the
//  message is failed. Another resend that ran meanwhile has counted its send: the first
//  one must count on top of it, not write back its own older copy.
//
//  Real pieces: connected PQSSessions (`connectedPair` through `startAcceptRig`), the
//  sender's real outbound job, accept ledger and deadlines (shortened through the test
//  seam), the sender's real SessionCache, and the entry points the host calls on a
//  registration (`resendUnackedOutboundEnvelopes`), on Retry
//  (`retryFailedServerAcceptOutbound`) and on a server accept
//  (`confirmServerAcceptedEnvelope`). Doubles: the server (`HeldEnvelopeServer`), and the
//  moment a call lands, which `DuringSend` pins to while the sender's send of one envelope
//  is still in flight.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

/// Runs one action when the armed envelope next reaches the server, inside the sender's
/// `sendMessage` for that copy: the way an accept the read loop handles, or a registration
/// that lands, before the send returns.
actor DuringSend {
    private var armed: (envelope: String, action: @Sendable () async -> Void)?

    func arm(_ envelope: String, _ action: @escaping @Sendable () async -> Void) {
        armed = (envelope, action)
    }

    func take(_ envelope: String) -> (@Sendable () async -> Void)? {
        guard let armed, armed.envelope == envelope else { return nil }
        self.armed = nil
        return armed.action
    }

    var fired: Bool { armed == nil }
}

extension EndToEndTests {
    func startLedgerRig() async throws -> (AcceptRig, DuringSend) {
        let during = DuringSend()
        let rig = try await startAcceptRig(onIngest: { frame, _, _ in
            if let action = await during.take(frame.messageId) { await action() }
        })
        return (rig, during)
    }

    /// What follows on a device while the ledger still holds `envelope`: in-place resends
    /// until read-side silence, the host's replay on the next registration, then the end of
    /// the next accept window. Bounded, because an envelope the ledger no longer holds never
    /// gets there.
    func runOutAcceptBudgetIfTracked(_ rig: AcceptRig, _ envelope: String) async {
        let alice = rig.pair.alice
        let silent = rig.silent
        let sink = rig.sink
        let exhaustedLine = "pqs.send.ackOverdueExhausted envelopeMessageId=\(envelope)"
        let silentBefore = await silent.ids.filter { $0 == envelope }.count
        let exhaustedBefore = sink.lines(containing: exhaustedLine).count
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        if await pollUntil(timeout: 5, { await silent.ids.filter { $0 == envelope }.count > silentBefore }) {
            await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
            await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
            await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
            await alice.rearmAllServerAcceptDeadlines()
            _ = await pollUntil(timeout: 5) { sink.lines(containing: exhaustedLine).count > exhaustedBefore }
        }
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
    }

    /// Runs in-place resends of `envelope` until PQS reports read-side silence.
    func resendInPlaceUntilSilent(_ rig: AcceptRig, _ envelope: String) async throws {
        let alice = rig.pair.alice
        let silent = rig.silent
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        let silenced = await pollUntil(timeout: 30) { await silent.contains(envelope) }
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
        try #require(silenced, "setup: the in-place resends ran until read-side silence")
    }

    // MARK: - A server accept during the send

    @Test("An accept that lands during a registration resend is not tracked again")
    func acceptDuringRegistrationResendIsNotTrackedAgain() async throws {
        let (rig, during) = try await startLedgerRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        await during.arm(pending) { await alice.confirmServerAcceptedEnvelope(pending) }

        await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        try #require(await during.fired, "setup: the accept landed during the registration resend")
        try #require(await rig.server.copyCount(of: pending) == 2, "setup: the registration resent the envelope")
        let accepted = try await rowState(rig)
        try #require(accepted == .waitingDelivery, "setup: the accept moved the message past sending")

        #expect(await alice.isAwaitingServerAccept(pending) == false, "an accepted envelope must leave the ledger")
        #expect(await alice.messagePipeline.unackedServerAcceptDeadlineTasks[pending] == nil, "no accept deadline for an accepted envelope")
        await runOutAcceptBudgetIfTracked(rig, pending)
        let copies = await rig.server.copyCount(of: pending)
        #expect(copies == 2, "an accepted envelope must not be resent: \(copies) copies")
        let observed = try await rowState(rig)
        #expect(observed == .waitingDelivery, "an accepted message must not fail: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    /// Control: the in-place resend already checks the ledger after its send.
    @Test("Control: an accept that lands during an in-place resend is not tracked again")
    func acceptDuringInPlaceResendIsNotTrackedAgain() async throws {
        let (rig, during) = try await startLedgerRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        await during.arm(pending) { await alice.confirmServerAcceptedEnvelope(pending) }

        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        let landed = await pollUntil(timeout: 30) { await alice.isAwaitingServerAccept(pending) == false }
        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
        let fired = await during.fired
        try #require(landed && fired, "setup: the accept landed during the in-place resend")
        try #require(await rig.server.copyCount(of: pending) == 2, "setup: the deadline resent the envelope in place")
        await jobLoopIdle(alice)

        #expect(await alice.isAwaitingServerAccept(pending) == false, "an accepted envelope must leave the ledger")
        #expect(await alice.messagePipeline.unackedServerAcceptDeadlineTasks[pending] == nil, "no accept deadline for an accepted envelope")
        await runOutAcceptBudgetIfTracked(rig, pending)
        let copies = await rig.server.copyCount(of: pending)
        #expect(copies == 2, "an accepted envelope must not be resent: \(copies) copies")
        let observed = try await rowState(rig)
        #expect(observed == .waitingDelivery, "an accepted message must not fail: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    @Test("An accept that lands during a retry of the failed message is not tracked again")
    func acceptDuringRetryIsNotTrackedAgain() async throws {
        let (rig, during) = try await startLedgerRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await exhaustAcceptBudget(rig, for: [pending])
        let failed = try await rowState(rig)
        try #require(failed == .failed("serverAcceptExhausted"), "setup: the message failed first")
        let copiesBeforeRetry = await rig.server.copyCount(of: pending)
        await during.arm(pending) { await alice.confirmServerAcceptedEnvelope(pending) }

        let retried = await alice.retryFailedServerAcceptOutbound(localMessageId: rig.localId)
        try #require(await during.fired, "setup: the accept landed during the retry's send")
        try #require(await rig.server.copyCount(of: pending) == copiesBeforeRetry + 1, "setup: the retry resent the envelope")
        let accepted = try await rowState(rig)
        try #require(accepted == .waitingDelivery, "setup: the accept moved the message past sending")

        #expect(retried, "the retry sent the envelope")
        #expect(await alice.isAwaitingServerAccept(pending) == false, "an accepted envelope must leave the ledger")
        #expect(await alice.messagePipeline.unackedServerAcceptDeadlineTasks[pending] == nil, "no accept deadline for an accepted envelope")
        await runOutAcceptBudgetIfTracked(rig, pending)
        let copies = await rig.server.copyCount(of: pending)
        #expect(copies == copiesBeforeRetry + 1, "an accepted envelope must not be resent: \(copies - copiesBeforeRetry - 1) more copies")
        let observed = try await rowState(rig)
        #expect(observed == .waitingDelivery, "an accepted message must not fail again: observed \(String(describing: observed))")
        await finishRig(rig)
    }

    // MARK: - Another resend during the send

    /// The deadline's in-place resend is in flight when a registration resends the same
    /// envelope. Both sends count against the budget of resends.
    @Test("A registration during an in-place resend keeps both resends counted")
    func registrationDuringInPlaceResendKeepsBothCounted() async throws {
        let (rig, during) = try await startLedgerRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        await during.arm(pending) {
            await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigLongDeadline)
            await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        }

        await alice.messagePipeline.testSetAckDeadlineNanosecondsForTests(Self.acceptRigShortDeadline)
        await alice.rearmAllServerAcceptDeadlines()
        let sink = rig.sink
        let inPlaceDone = await pollUntil(timeout: 30) {
            sink.contains("pqs.send.ackOverdueResend envelopeMessageId=\(pending) ")
        }
        let fired = await during.fired
        try #require(inPlaceDone && fired, "setup: the registration landed during the in-place resend")
        try #require(await rig.server.copyCount(of: pending) == 3, "setup: the original, the in-place resend and the registration resend")

        let attempts = await alice.messagePipeline.unackedServerAcceptByEnvelopeId[pending]?.resendAttempts
        #expect(attempts == 2, "two resends went out: attempts \(String(describing: attempts))")
        try await resendInPlaceUntilSilent(rig, pending)
        let copies = await rig.server.copyCount(of: pending)
        #expect(copies == 1 + 5, "the original plus a budget of five resends: \(copies) copies")
        await finishRig(rig)
    }

    /// One registration's resend is in flight when the next registration resends the same
    /// envelope.
    @Test("A registration during a registration resend keeps both resends counted")
    func registrationDuringRegistrationResendKeepsBothCounted() async throws {
        let (rig, during) = try await startLedgerRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        await during.arm(pending) { await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered") }

        await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        try #require(await during.fired, "setup: the second registration landed during the first one's send")
        try #require(await rig.server.copyCount(of: pending) == 3, "setup: the original and one resend per registration")

        let attempts = await alice.messagePipeline.unackedServerAcceptByEnvelopeId[pending]?.resendAttempts
        #expect(attempts == 2, "two resends went out: attempts \(String(describing: attempts))")
        try await resendInPlaceUntilSilent(rig, pending)
        let copies = await rig.server.copyCount(of: pending)
        #expect(copies == 1 + 5, "the original plus a budget of five resends: \(copies) copies")
        await finishRig(rig)
    }
}
