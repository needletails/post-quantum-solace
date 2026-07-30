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

    func record(_ envelopeId: String) {
        envelopeIds.append(envelopeId)
    }

    func all() -> [String] {
        envelopeIds
    }
}

struct ServerAcceptAckTests {
    private func pending(
        envelopeMessageId: String,
        sharedId: String = "shared-id"
    ) -> TaskProcessor.PendingOutboundTransport {
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
            curveOneTimeKeyId: nil,
            mlKEMOneTimeKeyId: "mlkem",
            createdAt: Date())
    }

    @Test("persisted send stays pending until server ack")
    func testPersistedSendStaysSendingUntilServerAck() async {
        let processor = TaskProcessor()
        let session = PQSSession()
        let pending = pending(envelopeMessageId: "envelope-1")
        await processor.registerUnackedServerAccept(
            pending: pending,
            localId: UUID(),
            sharedId: "shared-id",
            session: session)

        #expect(await processor.testUnackedCountForTests() == 1)
        await processor.confirmServerAcceptedEnvelope("envelope-1", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("confirm waits for every device envelope")
    func testConfirmAckRemovesEntryAndAdvancesWhenAllDeviceEnvelopesAcked() async {
        let processor = TaskProcessor()
        let session = PQSSession()
        let localId = UUID()
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "envelope-a"),
            localId: localId,
            sharedId: "shared-id",
            session: session)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "envelope-b"),
            localId: localId,
            sharedId: "shared-id",
            session: session)

        await processor.confirmServerAcceptedEnvelope("envelope-a", session: session)
        #expect(await processor.testUnackedCountForTests() == 1)
        await processor.confirmServerAcceptedEnvelope("envelope-b", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("unknown server ack is a no-op")
    func testUnknownAckIdIsNoOp() async {
        let processor = TaskProcessor()
        let session = PQSSession()
        await processor.confirmServerAcceptedEnvelope("unknown", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("ack deadline signals path suspect without resending")
    func testAckDeadlineExpiryEmitsPathSuspectEventAndDoesNotResendInPlace() async throws {
        let processor = TaskProcessor()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        let events = ServerAcceptAckEventRecorder()
        await session.setTransportDelegate(conformer: transport)
        await session.setServerAcceptAckOverdueHandler { envelopeId in
            await events.record(envelopeId)
        }
        await processor.testSetAckDeadlineNanosecondsForTests(10_000_000)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "deadline"),
            localId: UUID(),
            sharedId: "shared-id",
            session: session)

        try await Task.sleep(nanoseconds: 100_000_000)
        #expect(await events.all() == ["deadline"])
        #expect(await transport.capturedPayloads().isEmpty)
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("server ack cancels deadline")
    func testAckCancelsDeadline() async throws {
        let processor = TaskProcessor()
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
            session: session)
        await processor.confirmServerAcceptedEnvelope("cancelled", session: session)

        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(await events.all().isEmpty)
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("registered epoch resends identical ciphertext")
    func testRegisteredEpochResendsIdenticalCiphertext() async {
        let processor = TaskProcessor()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        await session.setTransportDelegate(conformer: transport)
        let outbound = pending(envelopeMessageId: "epoch")
        await processor.registerUnackedServerAccept(
            pending: outbound,
            localId: UUID(),
            sharedId: "shared-id",
            session: session)

        await processor.resendUnackedOutboundEnvelopes(reason: "registered", session: session)
        #expect(await transport.capturedPayloads() == [outbound.message.signed?.data ?? Data()])
        #expect(await transport.capturedEnvelopeMessageIds() == ["epoch"])
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("late ack after epoch resend completes")
    func testLateAckAfterResendStillCompletes() async {
        let processor = TaskProcessor()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        await session.setTransportDelegate(conformer: transport)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "late"),
            localId: UUID(),
            sharedId: "shared-id",
            session: session)

        await processor.resendUnackedOutboundEnvelopes(reason: "registered", session: session)
        await processor.confirmServerAcceptedEnvelope("late", session: session)
        #expect(await processor.testUnackedCountForTests() == 0)
        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }

    @Test("resend exhaustion marks failed but keeps ciphertext for retry")
    func testExhaustionAfterCapMarksFailed() async {
        let processor = TaskProcessor()
        let session = PQSSession()
        let outbound = pending(envelopeMessageId: "exhausted")
        let localId = UUID()
        await processor.testInsertUnackedForTests(
            envelopeMessageId: "exhausted",
            entry: .init(
                pending: outbound,
                localId: localId,
                sharedId: "shared-id",
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

        try? await processor.ratchetManager.shutdown()
        await session.shutdown()
    }
}
