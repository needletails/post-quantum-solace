//
//  ServerAcceptAckTests.swift
//  post-quantum-solace
//

import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
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
        sharedId: String = "shared-id",
        secretName: String = "bob",
        recipient: MessageRecipient? = nil
    ) -> MessagePipeline.PendingOutboundTransport {
        .init(
            message: SignedRatchetMessage(outOfBandPlaceholder: ()),
            metadata: .init(
                secretName: secretName,
                deviceId: UUID(),
                recipient: recipient ?? .nickname(secretName),
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

    private func makeSessionContext(
        secretName: String,
        databaseKey: Data
    ) throws -> SessionContext {
        let crypto = NeedleTailCrypto()
        let mlkem = try crypto.generateMLKem1024PrivateKey()
        let deviceId = UUID()
        return SessionContext(
            sessionUser: SessionUser(
                secretName: secretName,
                deviceId: deviceId,
                deviceKeys: DeviceKeys(
                    deviceId: deviceId,
                    signingPrivateKey: Data(repeating: 1, count: 32),
                    longTermPrivateKey: Data(repeating: 2, count: 32),
                    oneTimePrivateKeys: [],
                    mlKEMOneTimePrivateKeys: [],
                    finalMLKEMPrivateKey: try MLKEMPrivateKey(id: UUID(), mlkem.encode()))),
            databaseEncryptionKey: databaseKey,
            sessionContextId: 1,
            activeUserConfiguration: UserConfiguration(
                signingPublicKey: Data(),
                signedDevices: [],
                signedOneTimePublicKeys: [],
                signedMLKEMOneTimePublicKeys: []),
            registrationState: .registered)
    }

    private func makeSendingMessage(
        id: UUID,
        symmetricKey: SymmetricKey
    ) throws -> EncryptedMessage {
        try EncryptedMessage(
            id: id,
            communicationId: UUID(),
            sessionContextId: 1,
            sharedId: "shared-id",
            sequenceNumber: 1,
            props: .init(
                id: id,
                base: BaseCommunication(id: UUID(), data: Data()),
                sentDate: Date(),
                receiveDate: nil,
                deliveryState: .sending,
                message: CryptoMessage(
                    text: "hello",
                    metadata: Data(),
                    recipient: .nickname("bob"),
                    sentDate: Date(),
                    destructionTime: nil),
                senderSecretName: "alice",
                senderDeviceId: UUID()),
            symmetricKey: symmetricKey)
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

    @Test("same-connection exhaustion keeps the bubble and signals recycle")
    func testAckDeadlineExhaustionRecyclesInsteadOfFailing() async throws {
        let processor = MessagePipeline()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        let silent = ServerAcceptAckEventRecorder()
        await session.setTransportDelegate(conformer: transport)
        await session.setServerAcceptReadSideSilentHandler { envelopeId in
            await silent.record(envelopeId)
        }
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
        await processor.handleServerAcceptAckOverdue(
            envelopeMessageId: "exhausted-deadline",
            session: session)
        #expect(await silent.all() == ["exhausted-deadline"])
        #expect(await processor.isAwaitingServerAccept("exhausted-deadline") == true)
        #expect(await processor.unackedServerAcceptByEnvelopeId["exhausted-deadline"]?.readSideRecycleConsumed == false)
        #expect(await transport.capturedPayloads().isEmpty)
        // Backlog rearm must not start another timer on the silent socket.
        await processor.rearmAllServerAcceptDeadlines(session: session)
        #expect(await processor.unackedServerAcceptDeadlineTasks["exhausted-deadline"] == nil)
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

    @Test("registration replays a silent envelope; the next miss fails the bubble")
    func testReplayAfterRecycleThenFail() async {
        let processor = MessagePipeline()
        let session = PQSSession()
        let transport = PreparedTransportProbe()
        let silent = ServerAcceptAckEventRecorder()
        await session.setTransportDelegate(conformer: transport)
        await session.setServerAcceptReadSideSilentHandler { envelopeId in
            await silent.record(envelopeId)
        }
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
        await processor.testSetAckDeadlineNanosecondsForTests(60_000_000_000)

        await processor.resendUnackedOutboundEnvelopes(reason: "IRC registered", session: session)
        #expect(await transport.capturedEnvelopeMessageIds() == ["exhausted"])
        #expect(await processor.unackedServerAcceptByEnvelopeId["exhausted"]?.readSideRecycleConsumed == true)
        #expect(await processor.unackedServerAcceptDeadlineTasks["exhausted"] != nil)

        await processor.handleServerAcceptAckOverdue(
            envelopeMessageId: "exhausted",
            session: session)
        // Second silent window: no recycle signal, no resend, entry kept for user Retry.
        #expect(await silent.all().isEmpty)
        #expect(await processor.isAwaitingServerAccept("exhausted") == true)
        #expect(await processor.unackedServerAcceptDeadlineTasks["exhausted"] == nil)
        #expect(await transport.capturedEnvelopeMessageIds() == ["exhausted"])

        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }

    @Test("gatesSentState is peer and personal only")
    func testGatesSentStatePeerAndPersonalOnly() async {
        let processor = MessagePipeline()
        let peer = MessagePipeline.UnackedOutboundEnvelope(
            pending: pending(envelopeMessageId: "peer", secretName: "bob"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            connectionEpoch: 0,
            resendAttempts: 0)
        let sibling = MessagePipeline.UnackedOutboundEnvelope(
            pending: pending(envelopeMessageId: "sibling", secretName: "alice"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            connectionEpoch: 0,
            resendAttempts: 0)
        let personal = MessagePipeline.UnackedOutboundEnvelope(
            pending: pending(
                envelopeMessageId: "personal",
                secretName: "alice",
                recipient: .personalMessage),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: true,
            connectionEpoch: 0,
            resendAttempts: 0)
        let ephemeral = MessagePipeline.UnackedOutboundEnvelope(
            pending: pending(envelopeMessageId: "ephemeral", secretName: "bob"),
            localId: UUID(),
            sharedId: "shared-id",
            isPersistedOutbound: false,
            connectionEpoch: 0,
            resendAttempts: 0)
        #expect(await processor.testGatesSentStateForTests(peer, mySecretName: "alice"))
        #expect(await processor.testGatesSentStateForTests(sibling, mySecretName: "alice") == false)
        #expect(await processor.testGatesSentStateForTests(personal, mySecretName: "alice"))
        #expect(await processor.testGatesSentStateForTests(ephemeral, mySecretName: "alice") == false)
        // Unknown local identity: fall back to gating on every persisted copy.
        #expect(await processor.testGatesSentStateForTests(sibling, mySecretName: nil))
        #expect(await processor.testGatesSentStateForTests(ephemeral, mySecretName: nil) == false)
    }

    @Test("peer accept advances sent without waiting on sibling")
    func testPeerAcceptAdvancesSentWithoutWaitingOnSibling() async throws {
        let processor = MessagePipeline()
        let session = PQSSession()
        let store = MockCache()
        let databaseKey = Data(repeating: 7, count: 32)
        await session.setSessionContext(try makeSessionContext(secretName: "alice", databaseKey: databaseKey))
        await session.setDatabaseDelegate(conformer: store)

        let localId = UUID()
        let symmetricKey = SymmetricKey(data: databaseKey)
        let message = try makeSendingMessage(id: localId, symmetricKey: symmetricKey)
        await store.storeMessage(message)

        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "peer", secretName: "bob"),
            localId: localId,
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)
        await processor.registerUnackedServerAccept(
            pending: pending(envelopeMessageId: "sibling", secretName: "alice"),
            localId: localId,
            sharedId: "shared-id",
            isPersistedOutbound: true,
            session: session)

        await processor.confirmServerAcceptedEnvelope("peer", session: session)
        #expect(await processor.isAwaitingServerAccept("peer") == false)
        #expect(await processor.isAwaitingServerAccept("sibling") == true)

        let cache = try #require(await session.cache)
        let advanced = try await cache.fetchMessage(id: localId)
        let props = await advanced.props(symmetricKey: symmetricKey)
        #expect(props?.deliveryState == .waitingDelivery)

        guard var sibling = await processor.unackedServerAcceptByEnvelopeId["sibling"] else {
            Issue.record("sibling envelope should still be awaiting accept")
            try? await processor.ratchetManager.flushAndClose()
            await session.shutdown()
            return
        }
        sibling.resendAttempts = 5
        sibling.readSideRecycleConsumed = true
        await processor.testInsertUnackedForTests(envelopeMessageId: "sibling", entry: sibling)
        await processor.handleServerAcceptAckOverdue(
            envelopeMessageId: "sibling",
            session: session)

        #expect(await processor.isAwaitingServerAccept("sibling") == true)
        let afterSiblingExhaustion = try await cache.fetchMessage(id: localId)
        let afterProps = await afterSiblingExhaustion.props(symmetricKey: symmetricKey)
        #expect(afterProps?.deliveryState == .waitingDelivery)

        try? await processor.ratchetManager.flushAndClose()
        await session.shutdown()
    }
}
