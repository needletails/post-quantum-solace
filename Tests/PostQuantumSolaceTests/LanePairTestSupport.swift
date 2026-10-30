//
//  LanePairTestSupport.swift
//  post-quantum-solace
//
//  Shared harness for two connected sessions (alice and bob) with transports
//  that can hold frames in flight, plus lane-row snapshots and inbound counters.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels
import DoubleRatchetKit

extension EndToEndTests {
    struct ConnectedPair {
        let alice: PQSSession
        let bob: PQSSession
        let aliceDeviceId: UUID
        let bobDeviceId: UUID
        let aliceTransport: _MockTransportDelegate
        let bobTransport: _MockTransportDelegate
        let aliceStore: MockIdentityStore
        let bobStore: MockIdentityStore
        let aliceTask: Task<Void, Never>
        let bobTask: Task<Void, Never>
        /// Reestablishment control frames seen on either transport.
        let controls: ControlCounter

        func finish() async {
            bobTransport.continuation?.finish()
            aliceTransport.continuation?.finish()
            _ = await aliceTask.value
            _ = await bobTask.value
        }
    }

    actor ControlCounter {
        var reestablishments = 0
        func saw(_ frame: ReceivedMessage) {
            if case .sessionReestablishment = frame.transportEvent { reestablishments += 1 }
        }
    }

    actor HeldFrames {
        var frames: [ReceivedMessage] = []
        func hold(_ frame: ReceivedMessage) { frames.append(frame) }
        func take() -> [ReceivedMessage] { defer { frames = [] }; return frames }
        var count: Int { frames.count }
    }

    /// One lane row as a session holds it for a peer device, with the private
    /// keys pinned in its ratchet snapshot.
    struct LaneRow: Equatable {
        let id: UUID
        let archived: Bool
        let stateOTK: UUID?
        let stateMLKEM: UUID?
    }

    func connectedPair(
        bobTrustProbe: PeerIdentityTrustProbe? = nil,
        aliceUnrecoverableProbe: OutboundUnrecoverableProbe? = nil,
        aliceAuditSink: (any PQSAuditSink)? = nil,
        bobAuditSink: (any PQSAuditSink)? = nil
    ) async throws -> ConnectedPair {
        if let aliceAuditSink {
            _senderSession = await PQSSession(configuration: SessionConfiguration(
                transport: _MockTransportDelegate(session: _senderSession, store: store),
                store: createSenderStore(),
                observer: senderReceiver,
                auditSink: aliceAuditSink))
            senderReceiver = ReceiverDelegate(session: _senderSession)
        }
        if let bobAuditSink {
            _recipientSession = await PQSSession(configuration: SessionConfiguration(
                transport: _MockTransportDelegate(session: _recipientSession, store: store),
                store: createRecipientStore(),
                observer: recipientReceiver,
                auditSink: bobAuditSink))
            recipientReceiver = ReceiverDelegate(session: _recipientSession)
        }
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        let sd = SessionDelegate(session: _senderSession, outboundUnrecoverableProbe: aliceUnrecoverableProbe)
        let rsd = SessionDelegate(session: _recipientSession, peerIdentityTrustProbe: bobTrustProbe)
        let aliceStore = MockIdentityStore(mockUserData: sMockUserData, session: _senderSession, isSender: true)
        let bobStore = MockIdentityStore(mockUserData: rMockUserData, session: _recipientSession, isSender: false)
        try await createSenderSession(store: aliceStore, transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: bobStore, transport: bobTransport, sessionDelegate: rsd)
        let alice = _senderSession
        let bob = _recipientSession
        let controls = ControlCounter()
        let aliceTask = Task {
            for await received in aliceStream where received.recipient == "alice" {
                await controls.saw(received)
                _ = try? await self.receiveIgnoringRecoverableErrors(alice, received: received)
            }
        }
        let bobTask = Task {
            for await received in bobStream where received.recipient == "bob" {
                await controls.saw(received)
                _ = try? await self.receiveIgnoringRecoverableErrors(bob, received: received)
            }
        }
        try await createFriendship(aliceSession: alice, sd: sd, bobSession: bob, rsd: rsd)
        let aliceDeviceId = try #require(await alice.sessionContext?.sessionUser.deviceId)
        let bobDeviceId = try #require(await bob.sessionContext?.sessionUser.deviceId)
        #expect(await pollUntil(timeout: 15) {
            await bob.hasActiveInboundSessionIdentity(secretName: "alice", deviceId: aliceDeviceId)
        })
        return ConnectedPair(
            alice: alice, bob: bob,
            aliceDeviceId: aliceDeviceId, bobDeviceId: bobDeviceId,
            aliceTransport: aliceTransport, bobTransport: bobTransport,
            aliceStore: aliceStore, bobStore: bobStore,
            aliceTask: aliceTask, bobTask: bobTask,
            controls: controls)
    }

    /// The peer-device lane set is still exactly `expected`: same single row, same
    /// snapshot keys, not archived.
    func expectSameLane(_ rows: [LaneRow], _ expected: LaneRow, _ label: String) {
        #expect(rows.map(\.id) == [expected.id], "\(label): rows \(rows.map(\.id)) vs \(expected.id)")
        #expect(rows.first?.archived == false, "\(label): archived")
        #expect(rows.first?.stateOTK == expected.stateOTK, "\(label): OTK \(String(describing: rows.first?.stateOTK)) vs \(String(describing: expected.stateOTK))")
        #expect(rows.first?.stateMLKEM == expected.stateMLKEM, "\(label): ML-KEM \(String(describing: rows.first?.stateMLKEM)) vs \(String(describing: expected.stateMLKEM))")
    }

    func rows(on session: PQSSession, peer: String, deviceId: UUID) async throws -> [LaneRow] {
        let cache = try #require(await session.cache)
        let key = try await session.getDatabaseSymmetricKey()
        var out: [LaneRow] = []
        for identity in try await cache.fetchSessionIdentities() {
            guard let p = await identity.props(symmetricKey: key), p.secretName == peer, p.deviceId == deviceId else { continue }
            out.append(LaneRow(
                id: identity.id,
                archived: p.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
                stateOTK: p.ratchetOneTimePrivateKey?.id,
                stateMLKEM: p.ratchetMLKEMPrivateKey?.id))
        }
        return out
    }

    func acceptedCount(_ session: PQSSession) async -> Int {
        await session.messagePipeline.inboundLaneSelectionStatsLog.filter { $0.winningLaneId != nil }.count
    }

    func inboundCount(_ session: PQSSession) async -> Int {
        await session.messagePipeline.inboundLaneSelectionStatsLog.count
    }

    /// Sends from `sender` and waits for `receiver` to run lane selection on one
    /// more frame; returns that frame's stats.
    func sendAndAwaitInbound(
        from sender: PQSSession, to recipient: String, on receiver: PQSSession, text: String
    ) async throws -> InboundLaneSelectionStats {
        let before = await inboundCount(receiver)
        try await sender.send(recipient: .nickname(recipient), text: text)
        #expect(await pollUntil(timeout: 20) { await self.inboundCount(receiver) > before }, "\(text) should reach lane selection")
        return try #require(await receiver.messagePipeline.inboundLaneSelectionStatsLog.dropFirst(before).first)
    }

    /// Three round trips: both handshakes finish and the 4.1 one-time-key
    /// retirement dance settles, so later snapshots compare key for key.
    func settleLanes(_ pair: ConnectedPair) async throws {
        for round in 1...3 {
            _ = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "settle a\(round)")
            _ = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "settle b\(round)")
        }
    }

    /// Makes the next outbound send on `session` find its routine ML-KEM rotation due.
    func makeRotationDue(on session: PQSSession) async throws {
        var context = try #require(await session.sessionContext)
        let pastDate = try #require(Calendar.current.date(
            byAdding: .day,
            value: -(PQSSessionConstants.keyRotationIntervalDays + 1),
            to: Date()))
        context.sessionUser.deviceKeys.rotateKeysDate = pastDate
        await session.setSessionContext(context)
    }

    func finalMLKEMKeyId(_ session: PQSSession) async throws -> UUID {
        try #require(await session.sessionContext?.sessionUser.deviceKeys.finalMLKEMPrivateKey.id)
    }
}
