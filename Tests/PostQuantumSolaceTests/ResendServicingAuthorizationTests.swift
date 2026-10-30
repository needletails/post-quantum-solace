//
//  ResendServicingAuthorizationTests.swift
//  post-quantum-solace
//
//  Out-of-band resend servicing re-encrypts stored plaintext to the requester.
//  The requester must be the device the cited envelope was addressed to;
//  anything else is refused without a plaintext lookup. A request may cite the
//  envelope id or, as a host re-arm does, the logical shared id.
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

/// Keeps every audit line so a test can assert what reached the injected sink.
final class RecordingAuditSink: PQSAuditSink, @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    var isEnabled: Bool { true }

    func configure(isEnabled: Bool) {}

    func log(_ channel: PQSAuditLog.Channel, _ message: @autoclosure () -> String, level: Level) {
        let line = message()
        lock.lock()
        defer { lock.unlock() }
        lines.append(line)
    }

    func contains(_ fragment: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return lines.contains { $0.contains(fragment) }
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

    @Test("a fresh pipeline audits the first resend request")
    func freshPipelineAuditsFirstResendRequest() async throws {
        defer { Task { await shutdownSessions() } }
        let sink = RecordingAuditSink()
        let aliceStore = createSenderStore()
        _senderSession = await PQSSession(configuration: SessionConfiguration(
            transport: _MockTransportDelegate(session: _senderSession, store: store),
            store: aliceStore,
            observer: senderReceiver,
            auditSink: sink))
        try await createSenderSession(
            store: aliceStore,
            transport: _MockTransportDelegate(session: _senderSession, store: store),
            sessionDelegate: SessionDelegate(session: _senderSession))

        // A relaunched sender services a resend request before any ratchet work.
        #expect(await _senderSession.messagePipeline.session == nil)
        try await _senderSession.handleOutOfBandResendRequest(
            from: rMockUserData.rsn,
            deviceId: UUID(),
            failedSharedMessageIds: ["fresh-process-\(UUID().uuidString)"])

        #expect(sink.contains("pqs.recovery.resendRequestReceived"))
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

    @Test("a logical shared id is serviced when it names an envelope addressed to the requesting device")
    func logicalSharedIdAddressedToRequesterIsServiced() async throws {
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

        // A host re-arm from the placeholder ledger cites the logical id, not the
        // envelope id (S12a). It resolves only through the MessageRecord Alice wrote
        // for Bob's device, so Bob gets nothing that was not already addressed to him.
        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: bob,
            deviceId: bobDeviceId,
            failedSharedMessageIds: [sharedId])
        await _senderSession.waitForOutboundJobDrain()

        #expect(result.queuedIds == [sharedId])
        #expect(result.permanentlyUnavailableIds.isEmpty)
        let replayed = await log.contains(after: sentBefore) {
            $0.recipient == bob && $0.logicalMessageId == sharedId
        }
        #expect(replayed, "the replay must reach the device that asked for it")
    }

    @Test("a logical shared id of content addressed to another device is refused")
    func logicalSharedIdAddressedElsewhereIsRefused() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bobDeviceId, alice, bob) = try await setUpAliceBobWithAliceChild()

        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }

        let noteSharedId = "private-note-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .personalMessage,
            text: "only for my own devices",
            sharedIdOverride: noteSharedId)
        await _senderSession.waitForOutboundJobDrain()
        _ = try #require(await log.first {
            $0.logicalMessageId == noteSharedId && $0.recipient == alice
        })
        let sentBefore = await log.count()

        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: bob,
            deviceId: bobDeviceId,
            failedSharedMessageIds: [noteSharedId])
        await _senderSession.waitForOutboundJobDrain()

        #expect(result.queuedIds.isEmpty)
        #expect(result.permanentlyUnavailableIds == [noteSharedId])
        let leaked = await log.contains(after: sentBefore) {
            $0.recipient == bob && $0.logicalMessageId == noteSharedId
        }
        #expect(!leaked, "a logical id must not reach plaintext addressed to another device")
    }

    @Test("a linked device's logical-id request is serviced by the content owner")
    func siblingLogicalSharedIdIsServiced() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, _, alice, bob) = try await setUpAliceBobWithAliceChild()
        let childDeviceId = try #require(
            await _senderChildSession1.sessionContext?.sessionUser.deviceId)

        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }

        let sharedId = "dm-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname(bob),
            text: "hello bob",
            sharedIdOverride: sharedId)
        await _senderSession.waitForOutboundJobDrain()
        // The DM also fanned out to Alice's own linked device.
        _ = try #require(await log.first {
            $0.logicalMessageId == sharedId && $0.recipientDeviceId == childDeviceId
        })

        // Dogfood 2026-10-27: the sibling re-armed its placeholder by logical id and
        // was deferred as "not content owner" on every drain boundary for four days.
        let result = try await _senderSession.handleOutOfBandResendRequest(
            from: alice,
            deviceId: childDeviceId,
            failedSharedMessageIds: [sharedId])
        await _senderSession.waitForOutboundJobDrain()

        #expect(result.queuedIds == [sharedId])
        #expect(result.permanentlyUnavailableIds.isEmpty)
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
