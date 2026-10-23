//
//  RoutineRotationLaneTests.swift
//  post-quantum-solace
//
//  Routine ML-KEM rotation behaves like Signal's signed-prekey rotation: it
//  refreshes the published bundle for lanes that have not started yet and never
//  touches an established lane. Re-keying an established lane from the outbound
//  hot path is a spontaneous epoch the peer can only mirror in order; frames
//  already in flight, or a peer rotating at the same moment, diverge the chains.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels
import DoubleRatchetKit

extension EndToEndTests {
    private struct ConnectedPair {
        let alice: PQSSession
        let bob: PQSSession
        let aliceDeviceId: UUID
        let bobDeviceId: UUID
        let aliceTransport: _MockTransportDelegate
        let bobTransport: _MockTransportDelegate
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

    private actor ControlCounter {
        var reestablishments = 0
        func saw(_ frame: ReceivedMessage) {
            if case .sessionReestablishment = frame.transportEvent { reestablishments += 1 }
        }
    }

    private actor HeldFrames {
        var frames: [ReceivedMessage] = []
        func hold(_ frame: ReceivedMessage) { frames.append(frame) }
        func take() -> [ReceivedMessage] { defer { frames = [] }; return frames }
        var count: Int { frames.count }
    }

    /// One lane row as a session holds it for a peer device, with the private
    /// keys pinned in its ratchet snapshot.
    private struct LaneRow: Equatable {
        let id: UUID
        let archived: Bool
        let stateOTK: UUID?
        let stateMLKEM: UUID?
    }

    private func connectedPair() async throws -> ConnectedPair {
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            bobTransport.continuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            aliceTransport.continuation = continuation
        }
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: createSenderStore(), transport: aliceTransport, sessionDelegate: sd)
        try await createRecipientSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: rsd)
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
            aliceTask: aliceTask, bobTask: bobTask,
            controls: controls)
    }

    /// The peer-device lane set is still exactly `expected`: same single row, same
    /// snapshot keys, not archived.
    private func expectSameLane(_ rows: [LaneRow], _ expected: LaneRow, _ label: String) {
        #expect(rows.map(\.id) == [expected.id], "\(label): rows \(rows.map(\.id)) vs \(expected.id)")
        #expect(rows.first?.archived == false, "\(label): archived")
        #expect(rows.first?.stateOTK == expected.stateOTK, "\(label): OTK \(String(describing: rows.first?.stateOTK)) vs \(String(describing: expected.stateOTK))")
        #expect(rows.first?.stateMLKEM == expected.stateMLKEM, "\(label): ML-KEM \(String(describing: rows.first?.stateMLKEM)) vs \(String(describing: expected.stateMLKEM))")
    }

    private func rows(on session: PQSSession, peer: String, deviceId: UUID) async throws -> [LaneRow] {
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

    private func acceptedCount(_ session: PQSSession) async -> Int {
        await session.messagePipeline.inboundLaneSelectionStatsLog.filter { $0.winningLaneId != nil }.count
    }

    private func inboundCount(_ session: PQSSession) async -> Int {
        await session.messagePipeline.inboundLaneSelectionStatsLog.count
    }

    /// Sends from `sender` and waits for `receiver` to run lane selection on one
    /// more frame; returns that frame's stats.
    private func sendAndAwaitInbound(
        from sender: PQSSession, to recipient: String, on receiver: PQSSession, text: String
    ) async throws -> InboundLaneSelectionStats {
        let before = await inboundCount(receiver)
        try await sender.send(recipient: .nickname(recipient), text: text)
        #expect(await pollUntil(timeout: 20) { await self.inboundCount(receiver) > before }, "\(text) should reach lane selection")
        return try #require(await receiver.messagePipeline.inboundLaneSelectionStatsLog.dropFirst(before).first)
    }

    /// Three round trips: both handshakes finish and the 4.1 one-time-key
    /// retirement dance settles, so later snapshots compare key for key.
    private func settleLanes(_ pair: ConnectedPair) async throws {
        for round in 1...3 {
            _ = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "settle a\(round)")
            _ = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "settle b\(round)")
        }
    }

    /// Makes the next outbound send on `session` find its routine ML-KEM rotation due.
    private func makeRotationDue(on session: PQSSession) async throws {
        var context = try #require(await session.sessionContext)
        let pastDate = try #require(Calendar.current.date(
            byAdding: .day,
            value: -(PQSSessionConstants.keyRotationIntervalDays + 1),
            to: Date()))
        context.sessionUser.deviceKeys.rotateKeysDate = pastDate
        await session.setSessionContext(context)
    }

    private func finalMLKEMKeyId(_ session: PQSSession) async throws -> UUID {
        try #require(await session.sessionContext?.sessionUser.deviceKeys.finalMLKEMPrivateKey.id)
    }

    @Test("routine ML-KEM rotation changes the published final key but leaves an established lane's keys alone")
    func routineRotationLeavesEstablishedLaneAlone() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }

        try await settleLanes(pair)
        let aliceRow = try #require(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        let bobRow = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first)
        #expect(aliceRow.stateMLKEM != nil, "an established lane pins its ML-KEM key in the snapshot")
        let finalBefore = try await finalMLKEMKeyId(pair.alice)

        try await makeRotationDue(on: pair.alice)
        let stats = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "first send with rotation due")

        let finalAfter = try await finalMLKEMKeyId(pair.alice)
        #expect(finalAfter != finalBefore, "the routine rotation ran and replaced the published final key")
        let rotateDate = try #require(await pair.alice.sessionContext?.sessionUser.deviceKeys.rotateKeysDate)
        #expect(rotateDate > Date().addingTimeInterval(-60), "the rotation date is reset")

        expectSameLane(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId), aliceRow,
                       "alice's lane after her rotation send")
        #expect(stats.winningLaneId == bobRow.id && stats.attempts.count == 1,
                "bob decrypts on his established row without an epoch: \(stats.candidateOrder)")
        expectSameLane(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId), bobRow, "bob's lane")

        _ = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "reply after rotation")
        expectSameLane(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId), aliceRow,
                       "alice's lane after bob's reply")
        #expect(await pair.controls.reestablishments == 0, "no reestablishment control traffic")
        await pair.finish()
    }

    @Test("every frame in flight across a routine rotation decrypts, beyond the old 32-key epoch stash")
    func framesInFlightAcrossRoutineRotationAllDecrypt() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }

        try await settleLanes(pair)

        // Bob's frames leave his device but have not reached alice yet.
        let held = HeldFrames()
        pair.bobTransport.shouldDeliver = { received in
            guard received.recipient == "alice", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        let inFlight = 40
        for i in 1...inFlight {
            try await pair.bob.send(recipient: .nickname("alice"), text: "in flight \(i)")
        }
        #expect(await pollUntil(timeout: 20) { await held.count == inFlight })

        // Alice's rotation comes due and her next send runs it.
        try await makeRotationDue(on: pair.alice)
        let finalBefore = try await finalMLKEMKeyId(pair.alice)
        let crossing = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice sends during bob's flight")
        #expect(crossing.winningLaneId != nil && crossing.attempts.count == 1, "\(crossing.candidateOrder)")
        #expect(try await finalMLKEMKeyId(pair.alice) != finalBefore, "the rotation ran")

        // Now bob's frames land. None may fail: alice's receiving chain was never reset.
        pair.bobTransport.shouldDeliver = nil
        let acceptedBefore = await acceptedCount(pair.alice)
        for frame in await held.take() { pair.bobTransport.continuation?.yield(frame) }
        let allLanded = await pollUntil(timeout: 30) { await self.acceptedCount(pair.alice) >= acceptedBefore + inFlight }
        let landed = await acceptedCount(pair.alice) - acceptedBefore
        #expect(allLanded, "all \(inFlight) frames sent before the rotation decrypt; got \(landed)")
        let aliceRows = try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId)
        #expect(aliceRows.count == 1 && !aliceRows[0].archived, "no lane was re-minted or archived to recover")
        await pair.finish()
    }

    @Test("both devices rotating routinely with sends crossing stay in sync with no recovery")
    func crossingRoutineRotationsStayInSync() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }

        try await settleLanes(pair)
        let aliceRow = try #require(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        let bobRow = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first)

        try await makeRotationDue(on: pair.alice)
        try await makeRotationDue(on: pair.bob)

        // Each side sends, and so rotates, before seeing the other's frame.
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        pair.bobTransport.shouldDeliver = { received in
            guard received.recipient == "alice", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        let aliceFinalBefore = try await finalMLKEMKeyId(pair.alice)
        let bobFinalBefore = try await finalMLKEMKeyId(pair.bob)
        try await pair.alice.send(recipient: .nickname("bob"), text: "alice crossing rotation")
        try await pair.bob.send(recipient: .nickname("alice"), text: "bob crossing rotation")
        #expect(await pollUntil(timeout: 20) { await held.count == 2 })
        #expect(try await finalMLKEMKeyId(pair.alice) != aliceFinalBefore, "alice rotated")
        #expect(try await finalMLKEMKeyId(pair.bob) != bobFinalBefore, "bob rotated")

        pair.aliceTransport.shouldDeliver = nil
        pair.bobTransport.shouldDeliver = nil
        let aliceAcceptedBefore = await acceptedCount(pair.alice)
        let bobAcceptedBefore = await acceptedCount(pair.bob)
        for frame in await held.take() {
            if frame.recipient == "bob" { pair.aliceTransport.continuation?.yield(frame) }
            else { pair.bobTransport.continuation?.yield(frame) }
        }
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.bob) > bobAcceptedBefore }, "bob decrypts alice's crossing frame")
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.alice) > aliceAcceptedBefore }, "alice decrypts bob's crossing frame")

        // Live traffic in both directions afterwards stays on the same rows.
        let a2 = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice after crossing")
        let b2 = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "bob after crossing")
        #expect(a2.winningLaneId == bobRow.id && a2.attempts.count == 1, "\(a2.candidateOrder)")
        #expect(b2.winningLaneId == aliceRow.id && b2.attempts.count == 1, "\(b2.candidateOrder)")
        expectSameLane(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId), aliceRow, "alice's lane")
        expectSameLane(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId), bobRow, "bob's lane")
        #expect(await pair.controls.reestablishments == 0,
                "no reestablishment was needed to recover")
        await pair.finish()
    }
}
