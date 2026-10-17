//
//  ChatFanoutDeviceCoverageTests.swift
//  post-quantum-solace
//
//  Bug report F1: a peer device linked after the sender already had a lane to
//  that account never received a copy of anything. The verified-device memo
//  froze, and even a cold start that saw the new device in the directory never
//  minted its lane because the warm-lane check read the memo the fetch had just
//  written. Every verified recipient device must get a lane and a copy.
//

import Foundation
import Testing
@testable import PQSSession
import SessionModels

extension EndToEndTests {
    /// Alice and Bob are friends with one lane each; Bob then links a second device.
    private func setUpBobWithLateLinkedChild() async throws -> (
        aliceTransport: _MockTransportDelegate,
        bob: String,
        bobMasterDeviceId: UUID,
        bobChildDeviceId: UUID
    ) {
        let aliceStore = createSenderStore()
        let bobStore = createRecipientStore()
        let bobChildStore = createRecipientChildStore1()
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

        // Bob links a new device after Alice already has a lane to his master.
        let childTransport = _MockTransportDelegate(session: _recipientChildSession1, store: store)
        try await linkRecipientChildSession1(
            store: bobChildStore,
            transport: childTransport,
            useProvidedTransport: true)

        let bobMasterDeviceId = try #require(await _recipientSession.sessionContext?.sessionUser.deviceId)
        let bobChildDeviceId = try #require(await _recipientChildSession1.sessionContext?.sessionUser.deviceId)
        return (aliceTransport, rMockUserData.rsn, bobMasterDeviceId, bobChildDeviceId)
    }

    private func sendAndCollectRecipientDevices(
        aliceTransport: _MockTransportDelegate,
        bob: String
    ) async throws -> Set<UUID> {
        let log = SentEnvelopeLog()
        aliceTransport.duringSendMessage = { received in await log.record(received) }
        let sharedId = "fanout-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname(bob),
            text: "to every one of your devices",
            sharedIdOverride: sharedId)
        await _senderSession.waitForOutboundJobDrain()
        let sent = await log.sent.filter { $0.logicalMessageId == sharedId && $0.recipient == bob }
        return Set(sent.compactMap(\.recipientDeviceId))
    }

    @Test("a cold start mints a lane for a verified device that has no row")
    func coldStartMintsLaneForVerifiedDeviceWithoutRow() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bob, bobMaster, bobChild) = try await setUpBobWithLateLinkedChild()

        // Process restart: the in-memory memos are gone, rows survive.
        await _senderSession.setVerifiedDeviceIds([], for: bob)
        await _senderSession.removeIdentity(with: bob)

        let devices = try await sendAndCollectRecipientDevices(aliceTransport: aliceTransport, bob: bob)
        #expect(devices.contains(bobMaster))
        #expect(devices.contains(bobChild), "the newly linked device must receive its own copy")
    }

    @Test("a warm memo expires and the next send consults the directory again")
    func warmMemoExpiresAndRefetches() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bob, bobMaster, bobChild) = try await setUpBobWithLateLinkedChild()

        // The friendship exchange left a fresh memo listing only Bob's master.
        await _senderSession.setVerifiedDeviceIds([bobMaster], for: bob)
        let beforeExpiry = try await sendAndCollectRecipientDevices(aliceTransport: aliceTransport, bob: bob)
        #expect(!beforeExpiry.contains(bobChild), "within the TTL the warm memo is trusted as-is")

        // Past the TTL the directory is consulted and the child is laned.
        let expiry = PQSSessionConstants.verifiedDeviceMemoTTLSeconds + 1
        await _senderSession.setClock { Date().addingTimeInterval(expiry) }
        let afterExpiry = try await sendAndCollectRecipientDevices(aliceTransport: aliceTransport, bob: bob)
        #expect(afterExpiry.contains(bobMaster))
        #expect(afterExpiry.contains(bobChild), "an expired memo must be refreshed from the directory")
    }

    @Test("a warm memo that lists a device without a row still mints its lane")
    func warmMemoWithUnlanedDeviceMintsLane() async throws {
        defer { Task { await shutdownSessions() } }
        let (aliceTransport, bob, bobMaster, bobChild) = try await setUpBobWithLateLinkedChild()

        // The directory has already told us about the child; only the lane is missing.
        await _senderSession.setVerifiedDeviceIds([bobMaster, bobChild], for: bob)

        let devices = try await sendAndCollectRecipientDevices(aliceTransport: aliceTransport, bob: bob)
        #expect(devices.contains(bobMaster))
        #expect(devices.contains(bobChild), "a verified device without a lane must be laned before fan-out")
    }
}
