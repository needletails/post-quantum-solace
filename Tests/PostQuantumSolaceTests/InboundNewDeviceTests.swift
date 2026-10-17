//
//  InboundNewDeviceTests.swift
//  post-quantum-solace
//
//  Bug report F3: the first frame from a peer's newly linked device arrived while
//  the host's lookup cache still served the pre-link snapshot. The forced refresh
//  wrote that snapshot into the verified-device memo, found no row, and the
//  stale-device policy dropped the frame and purged the only server copy.
//  A missing-row refresh must bypass the cache, and a drop may only follow a
//  live directory answer.
//

import Foundation
import Testing
@testable import PQSSession
import SessionModels

extension EndToEndTests {
    @Test("the first frame from a newly linked peer device is not dropped on a cached snapshot")
    func firstFrameFromNewlyLinkedDeviceIsNotPurged() async throws {
        defer { Task { await shutdownSessions() } }
        let aliceStore = createSenderStore()
        let aliceChildStore = createSenderChildStore1()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceDelegate = SessionDelegate(session: _senderSession)
        let bobDelegate = SessionDelegate(session: _recipientSession)

        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: aliceDelegate)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: bobDelegate)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: aliceDelegate,
            bobSession: _recipientSession,
            rsd: bobDelegate)

        let alice = sMockUserData.ssn
        let bob = rMockUserData.rsn
        // Bob's view of Alice before the new device exists.
        let preLinkSnapshot = try await store.findConfiguration(for: alice)

        // Alice links a second device; the live directory now lists it.
        let childTransport = _MockTransportDelegate(session: _senderChildSession1, store: store)
        try await linkSenderChildSession1(
            store: aliceChildStore,
            transport: childTransport,
            useProvidedTransport: true)
        let childDeviceId = try #require(await _senderChildSession1.sessionContext?.sessionUser.deviceId)

        // Bob's host cache keeps serving the pre-link snapshot for the next minutes.
        bobTransport.staleConfigurationBySecretName[alice] = preLinkSnapshot

        // Deliver the child's frames into Bob's session.
        let log = SentEnvelopeLog()
        childTransport.duringSendMessage = { received in await log.record(received) }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            childTransport.continuation = continuation
        }
        let bobLoop = Task {
            for await received in bobStream {
                _ = try? await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }
        defer {
            childTransport.continuation?.finish()
            bobLoop.cancel()
        }

        let sharedId = "new-device-first-\(UUID().uuidString)"
        try await _senderChildSession1.send(
            recipient: .nickname(bob),
            text: "hello from my new phone",
            sharedIdOverride: sharedId)
        await _senderChildSession1.waitForOutboundJobDrain()
        let envelope = try #require(await log.first { $0.logicalMessageId == sharedId })

        // Wait for Bob to either accept the frame or finish deciding its fate.
        var delivered = false
        var quarantined = false
        for _ in 0..<100 where !delivered && !quarantined {
            delivered = await bobStore.getAllMessages().contains { $0.sharedId == sharedId }
            quarantined = await _recipientSession.isInboundFailureQuarantined(
                sender: alice,
                deviceId: childDeviceId,
                messageId: envelope.messageId)
            if !delivered && !quarantined { try await Task.sleep(nanoseconds: 50_000_000) }
        }

        #expect(!quarantined, "a cached snapshot must never classify a just-linked device as retired")
        #expect(delivered, "Bob must decrypt the first frame once the live directory lists the new device")
        let memo = await _recipientSession.lastVerifiedDeviceIdsBySecretName[alice] ?? []
        #expect(memo.contains(childDeviceId), "the missing-row refresh must have consulted the live directory")
    }
}
