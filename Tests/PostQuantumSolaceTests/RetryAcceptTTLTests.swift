//
//  RetryAcceptTTLTests.swift
//  post-quantum-solace
//
//  The accept ledger forgets an envelope ten minutes after it was tracked and fails its
//  message. A Retry sends the envelope again and starts a new wait for the server's accept,
//  so that wait must not be cut short by the time the first send went out: a message that
//  failed, sat for more than ten minutes, and was then retried must still move past sending
//  when the server accepts the retried copy, also when another send or a registration runs
//  the ledger's cleanup before that accept arrives.
//
//  Real pieces: connected PQSSessions (`startAcceptRig`), the sender's real outbound job and
//  accept ledger, the real budget exhaustion (`exhaustAcceptBudget`), and the entry points the
//  host calls on Retry (`retryFailedServerAcceptOutbound`), on a send (`send`), on a
//  registration (`resendUnackedOutboundEnvelopes`) and on a server accept
//  (`confirmServerAcceptedEnvelope`). Doubles: the server (`HeldEnvelopeServer`), and the
//  passing of time, which the test applies by moving the tracked envelope's send time back
//  through the existing ledger seam (`testInsertUnackedForTests`).
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    enum LedgerCleanupTrigger: Sendable {
        /// The user sends another message.
        case send
        /// The connection registers again (e.g. the host recycled a silent socket).
        case registration
    }

    /// Moves the tracked envelope's first send `age` seconds into the past, as if the
    /// message had failed and the user waited that long before tapping Retry.
    func backdateTrackedEnvelope(_ rig: AcceptRig, _ envelope: String, by age: TimeInterval) async throws {
        let pipeline = await rig.pair.alice.messagePipeline
        var entry = try #require(await pipeline.unackedServerAcceptByEnvelopeId[envelope], "setup: the envelope is tracked")
        let pending = entry.pending
        entry.pending = MessagePipeline.PendingOutboundTransport(
            message: pending.message,
            metadata: pending.metadata,
            sessionIdentityId: pending.sessionIdentityId,
            x25519OneTimeKeyId: pending.x25519OneTimeKeyId,
            mlKEMOneTimeKeyId: pending.mlKEMOneTimeKeyId,
            createdAt: pending.createdAt.addingTimeInterval(-age))
        await pipeline.testInsertUnackedForTests(envelopeMessageId: envelope, entry: entry)
    }

    /// Fails the rig's message, lets `age` seconds pass, taps Retry, runs the ledger's
    /// cleanup through `trigger` before the accept arrives, then delivers the server's accept
    /// for the retried copy. Returns the row's state at the end.
    func retryAfterWaiting(_ age: TimeInterval, thenCleanupBy trigger: LedgerCleanupTrigger) async throws -> DeliveryState? {
        let rig = try await startAcceptRig()
        let alice = rig.pair.alice
        let pending = try await envelope(rig, "bob", rig.bobMaster)
        try await exhaustAcceptBudget(rig, for: [pending])
        let failed = try await rowState(rig)
        try #require(failed == .failed("serverAcceptExhausted"), "setup: the message failed first")
        try #require(await alice.isAwaitingServerAccept(pending), "setup: the failed envelope is still tracked")

        try await backdateTrackedEnvelope(rig, pending, by: age)

        let before = await rig.server.copyCount(of: pending)
        let retried = await alice.retryFailedServerAcceptOutbound(localMessageId: rig.localId)
        try #require(retried, "setup: the retry sent the envelope")
        try #require(await rig.server.copyCount(of: pending) == before + 1, "setup: the retried copy reached the server")
        let sending = try await rowState(rig)
        try #require(sending == .sending, "setup: the retry moved the message back to sending")

        switch trigger {
        case .send:
            let nextSharedId = "accept-ttl-next-\(UUID().uuidString)"
            try await alice.send(recipient: .nickname("bob"), text: "next", sharedIdOverride: nextSharedId)
            let pipeline = await alice.messagePipeline
            let tracked = await pollUntil(timeout: 30) {
                await pipeline.unackedServerAcceptByEnvelopeId.values.contains { $0.sharedId == nextSharedId }
            }
            try #require(tracked, "setup: the next message was sent and tracked")
        case .registration:
            await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        }

        // The server accepts the retried copy.
        await alice.confirmServerAcceptedEnvelope(pending)
        let observed = try await rowState(rig)
        await finishRig(rig)
        return observed
    }

    @Test("A retry of a message first sent over ten minutes ago survives the next send")
    func retryAfterAcceptTTLSurvivesTheNextSend() async throws {
        let observed = try await retryAfterWaiting(11 * 60, thenCleanupBy: .send)
        #expect(observed == .waitingDelivery, "the server accepted the retried message: observed \(String(describing: observed))")
    }

    @Test("A retry of a message first sent over ten minutes ago survives the next registration")
    func retryAfterAcceptTTLSurvivesTheNextRegistration() async throws {
        let observed = try await retryAfterWaiting(11 * 60, thenCleanupBy: .registration)
        #expect(observed == .waitingDelivery, "the server accepted the retried message: observed \(String(describing: observed))")
    }

    @Test("Control: a retry of a message first sent under ten minutes ago survives the next send")
    func retryWithinAcceptTTLSurvivesTheNextSend() async throws {
        let observed = try await retryAfterWaiting(9 * 60, thenCleanupBy: .send)
        #expect(observed == .waitingDelivery, "the server accepted the retried message: observed \(String(describing: observed))")
    }

    @Test("Control: a retry of a message first sent under ten minutes ago survives the next registration")
    func retryWithinAcceptTTLSurvivesTheNextRegistration() async throws {
        let observed = try await retryAfterWaiting(9 * 60, thenCleanupBy: .registration)
        #expect(observed == .waitingDelivery, "the server accepted the retried message: observed \(String(describing: observed))")
    }
}
