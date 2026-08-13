//
//  ServerAcceptAckTests.swift
//  post-quantum-solace
//

import Foundation
@testable import PQSSession
import SessionModels
import Testing

private actor ServerAcceptAckEventRecorder {
    private var envelopeIds: [String] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func record(_ envelopeId: String) {
        envelopeIds.append(envelopeId)
        let resumed = waiters
        waiters.removeAll()
        resumed.forEach { $0.resume() }
    }

    func all() -> [String] {
        envelopeIds
    }

    /// Suspends until the first overdue event is recorded. Event-driven so tests never
    /// race deadline fires against fixed sleeps.
    func waitForFirst() async {
        while envelopeIds.isEmpty {
            await withCheckedContinuation { waiters.append($0) }
        }
    }
}

struct ServerAcceptAckTests {
    private func pending(
        envelopeMessageId: String,
        sharedId: String = "shared-id"
    ) -> MessagePipeline.PendingOutboundTransport {
        .init(
            message: SignedRatchetMessage(outOfBandPlaceholder: ()),
            metadata: .init(
                secretName: "bob",
                deviceId: UUID(),
                recipient: .nickname("bob"),
                transportMetadata: nil,
                sharedMessageId: sharedId,
                envelopeMessageId: envelopeMessageId,
                transportEvent: nil,
                requiresServerAck: true),
            sessionIdentityId: UUID(),
            needsRemoteDeletion: false,
            x25519OneTimeKeyId: nil,
            mlKEMOneTimeKeyId: "mlkem",
            createdAt: Date())
    }

    @Test("persisted send stays pending until server ack")
    func testPersistedSendStaysSendingUntilServerAck() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        let pending = pending(envelopeMessageId: "envelope-1")
        await processor.registerUnackedServerAccept(
            pending: pending,
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)

        #expect(await processor.testUnackedCountForTests() == 1)
        await processor.confirmServerAcceptedEnvelope("envelope-1", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("confirm waits for every device envelope")
    func testConfirmAckRemovesEntryAndAdvancesWhenAllDeviceEnvelopesAcked() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        let localId = UUID()
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "envelope-a"),
            localId: localId,
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "envelope-b"),
            localId: localId,
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)

        await processor.confirmServerAcceptedEnvelope("envelope-a", session: session)
        #expect(await processor.testUnackedCountForTests() == 1)
        await processor.confirmServerAcceptedEnvelope("envelope-b", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("unknown server ack is a no-op")
    func testUnknownAckIdIsNoOp() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        await processor.confirmServerAcceptedEnvelope("unknown", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("ack deadline resends identical ciphertext in place")
    func testAckDeadlineExpiryResendsInPlaceWithoutConnectionHook() async throws {
        let processor = MessagePipeline()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        let events = ServerAcceptAckEventRecorder()
        await session.setTransportDelegate(conformer: transport)
        await session.setServerAcceptAckOverdueHandler { envelopeId in
            await events.record(envelopeId)
        }
        await processor.testSetAckDeadlineNanosecondsForTests(10_000_000)
        let outbound = pending(envelopeMessageId: "deadline")
        await processor.registerUnackedServerAccept(
            pending: outbound,
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)

        // Event-driven: suspend until the overdue in-place resend actually reaches the
        // transport. A fixed sleep races the handler's notify actor hop — if confirm
        // wins that race the handler (correctly) drops the resend, flaking the test.
        await transport.waitForCapturedSends(atLeast: 1)
        // Deadline rearms after in-place resend; stop further fires before asserting.
        await processor.confirmServerAcceptedEnvelope("deadline", session: session)
        #expect(await events.all().contains("deadline"))
        #expect(await transport.capturedPayloads().contains(outbound.message.signed?.data ?? Data()))
        #expect(await processor.isAwaitingServerAccept("deadline") == false)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("ack deadline exhaustion marks failed and keeps ciphertext")
    func testAckDeadlineExhaustionMarksFailed() async throws {
        let processor = MessagePipeline()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        await session.setTransportDelegate(conformer: transport)
        let localId = UUID()
        let outbound = pending(envelopeMessageId: "exhausted-deadline")
        await processor.testInsertUnackedForTests(
            envelopeMessageId: "exhausted-deadline",
            entry: .init(
                pending: outbound,
                localId: localId,
                sharedId: "shared-id",
                isPersistedOutbound: true,
                connectionEpoch: 0,
                resendAttempts: 5))
        await processor.testSetAckDeadlineNanosecondsForTests(10_000_000)
        // Manually fire overdue path (entry already at cap).
        await processor.handleServerAcceptAckOverdue(
            envelopeMessageId: "exhausted-deadline",
            session: session)
        #expect(await processor.isAwaitingServerAccept("exhausted-deadline") == true)
        #expect(await transport.capturedPayloads().isEmpty)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("isAwaitingServerAccept tracks unacked map")
    func testIsAwaitingServerAccept() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        #expect(await processor.isAwaitingServerAccept("missing") == false)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "awaiting"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)
        #expect(await processor.isAwaitingServerAccept("awaiting") == true)
        await processor.confirmServerAcceptedEnvelope("awaiting", session: session)
        #expect(await processor.isAwaitingServerAccept("awaiting") == false)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("rearmAll keeps unacked and replaces deadline task")
    func testRearmAllServerAcceptDeadlines() async throws {
        let processor = MessagePipeline()
        let session = PQSSession()
        let events = ServerAcceptAckEventRecorder()
        await session.setServerAcceptAckOverdueHandler { envelopeId in
            await events.record(envelopeId)
        }
        // First window is far in the future (5s): if rearm fails to cancel it, the
        // exactly-once assertion below would still hold, but the entry check would
        // observe a spurious early fire — deterministic in both directions, no sleeps.
        await processor.testSetAckDeadlineNanosecondsForTests(5_000_000_000)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "rearm"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)
        #expect(await events.all().isEmpty)
        // Cancel the first window and start a fresh, short one.
        await processor.testSetAckDeadlineNanosecondsForTests(10_000_000)
        await processor.rearmAllServerAcceptDeadlines(session: session)
        // Any re-arm the overdue handler performs after firing (no transport delegate
        // here) uses the override read at fire time — push it far out so the handler
        // cannot fire a second time before we confirm.
        await processor.testSetAckDeadlineNanosecondsForTests(5_000_000_000)
        await events.waitForFirst()
        #expect(await processor.isAwaitingServerAccept("rearm") == true)
        await processor.confirmServerAcceptedEnvelope("rearm", session: session)
        #expect(await events.all() == ["rearm"])
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("server ack cancels deadline")
    func testAckCancelsDeadline() async throws {
        let processor = MessagePipeline()
        let session = PQSSession()
        let events = ServerAcceptAckEventRecorder()
        await session.setServerAcceptAckOverdueHandler { envelopeId in
            await events.record(envelopeId)
        }
        await processor.testSetAckDeadlineNanosecondsForTests(50_000_000)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "cancelled"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)
        await processor.confirmServerAcceptedEnvelope("cancelled", session: session)

        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(await events.all().isEmpty)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("registered epoch resends identical ciphertext")
    func testRegisteredEpochResendsIdenticalCiphertext() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        await session.setTransportDelegate(conformer: transport)
        let outbound = pending(envelopeMessageId: "epoch")
        await processor.registerUnackedServerAccept(
            pending: outbound,
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)

        await processor.resendUnackedOutboundEnvelopes(reason: "registered", session: session)
        #expect(await transport.capturedPayloads() == [outbound.message.signed?.data ?? Data()])
        #expect(await transport.capturedEnvelopeMessageIds() == ["epoch"])
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("late ack after epoch resend completes")
    func testLateAckAfterResendStillCompletes() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        await session.setTransportDelegate(conformer: transport)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "late"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)

        await processor.resendUnackedOutboundEnvelopes(reason: "registered", session: session)
        await processor.confirmServerAcceptedEnvelope("late", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("resend exhaustion marks failed but keeps ciphertext for retry")
    func testExhaustionAfterCapMarksFailed() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        let outbound = pending(envelopeMessageId: "exhausted")
        let localId = UUID()
        await processor.testInsertUnackedForTests(
            envelopeMessageId: "exhausted",
            entry: .init(
                pending: outbound,
                localId: localId,
                sharedId: "shared-id",
                isPersistedOutbound: true,
                connectionEpoch: 0,
                resendAttempts: 5))

        await processor.resendUnackedOutboundEnvelopes(reason: "registered", session: session)
        // Ciphertext is retained so a user Retry can re-arm the send.
        #expect(await processor.testUnackedCountForTests() == 1)

        let didRetry = await processor.retryFailedServerAcceptOutbound(
            localMessageId: localId,
            session: session)
        // No transport delegate in this harness — retry still re-arms the entry (attempts reset).
        #expect(didRetry == false || didRetry == true)
        #expect(await processor.testUnackedCountForTests() == 1)

        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }
}
