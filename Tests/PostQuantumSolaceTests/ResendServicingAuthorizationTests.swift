//
//  ResendServicingAuthorizationTests.swift
//  post-quantum-solace
//
//  Out-of-band resend servicing re-encrypts stored plaintext to the requester.
//  The requester must be the device the cited envelope was addressed to;
//  anything else is refused without a plaintext lookup.
//

import Foundation
import Testing
@testable import PQSSession

/// Records every envelope a mock transport hands off.
actor SentEnvelopeLog {
    private(set) var sent: [ReceivedMessage] = []

    func record(_ message: ReceivedMessage) {
        sent.append(message)
    }

    func count() -> Int { sent.count }

    func first(where predicate: (ReceivedMessage) -> Bool) -> ReceivedMessage? {
        sent.first(where: predicate)
    }

    func contains(after index: Int, where predicate: (ReceivedMessage) -> Bool) -> Bool {
        sent.dropFirst(index).contains(where: predicate)
    }
}

extension EndToEndTests {
    private func setUpAliceBobWithAliceChild() async throws -> (
        aliceTransport: _MockTransportDelegate,
        bobDeviceId: UUID,
        alice: String,
        bob: String
    ) {
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
        try await linkSenderChildSession1(store: aliceChildStore, transport: aliceTransport)
        try await createFriendship(
            aliceSession: _senderSession,
            sd: aliceDelegate,
            bobSession: _recipientSession,
            rsd: bobDelegate)

        let bobDeviceId = try #require(
            await _recipientSession.sessionContext?.sessionUser.deviceId)
        return (aliceTransport, bobDeviceId, sMockUserData.ssn, rMockUserData.rsn)
    }

    @Test("resend servicing refuses an envelope addressed to another account")
    func crossRecipientResendIsRefused() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bobDeviceId, alice, bob) = try await setUpAliceBobWithAliceChild()

        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }

        // A personal note fans out only to Alice's own linked device.
        let noteSharedId = "private-note-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .personalMessage,
            text: "only for my own devices",
            sharedIdOverride: noteSharedId)
        await _senderSession.waitForOutboundJobDrain()

        let noteEnvelope = try #require(await log.first {
            $0.logicalMessageId == noteSharedId && $0.recipient == alice
        })
        let sentBefore = await log.count()

        // Bob (a contact with a live lane) cites the envelope Alice sent to her own device.
        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: bob,
            deviceId: bobDeviceId,
            failedSharedMessageIds: [noteEnvelope.messageId])
        await _senderSession.waitForOutboundJobDrain()

        #expect(result.queuedIds.isEmpty, "a foreign envelope must never be queued for replay")
        #expect(result.permanentlyUnavailableIds == [noteEnvelope.messageId])
        let leaked = await log.contains(after: sentBefore) {
            $0.recipient == bob && $0.logicalMessageId == noteSharedId
        }
        #expect(!leaked, "Alice must not re-encrypt a note addressed to her own device for Bob")
    }

    @Test("a bare logical shared id is not accepted in place of an envelope id")
    func bareSharedIdIsNotAcceptedAsEnvelopeId() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bobDeviceId, _, bob) = try await setUpAliceBobWithAliceChild()

        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }

        let sharedId = "dm-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname(bob),
            text: "hello bob",
            sharedIdOverride: sharedId)
        await _senderSession.waitForOutboundJobDrain()
        let sentBefore = await log.count()

        // Bob cites the logical id the server sees on every packet, not his envelope id.
        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: bob,
            deviceId: bobDeviceId,
            failedSharedMessageIds: [sharedId])
        await _senderSession.waitForOutboundJobDrain()

        #expect(result.queuedIds.isEmpty)
        #expect(result.permanentlyUnavailableIds == [sharedId])
        let replayed = await log.contains(after: sentBefore) {
            $0.recipient == bob && $0.logicalMessageId == sharedId
        }
        #expect(!replayed, "plaintext must only be looked up through an envelope record")
    }

    @Test("the addressed recipient device can still request its own envelope")
    func legitimateRecipientResendStillServices() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bobDeviceId, _, bob) = try await setUpAliceBobWithAliceChild()

        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }

        let sharedId = "dm-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname(bob),
            text: "please resend me",
            sharedIdOverride: sharedId)
        await _senderSession.waitForOutboundJobDrain()

        let bobEnvelope = try #require(await log.first {
            $0.logicalMessageId == sharedId && $0.recipientDeviceId == bobDeviceId
        })

        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: bob,
            deviceId: bobDeviceId,
            failedSharedMessageIds: [bobEnvelope.messageId])

        #expect(result.queuedIds == [bobEnvelope.messageId])
        #expect(result.permanentlyUnavailableIds.isEmpty)
    }
}
