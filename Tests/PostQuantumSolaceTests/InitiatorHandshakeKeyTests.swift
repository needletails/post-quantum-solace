//
//  InitiatorHandshakeKeyTests.swift
//  post-quantum-solace
//
//  An initiator's handshake keys never come from the published pool. The curve
//  slot of a first frame is X3DH's ephemeral: minted per lane, held only in that
//  lane's ratchet state, never published. The ML-KEM slot is the final key, the
//  signed-prekey role. Dogfood 2026-10-28: pool `.last` filled both slots, so every
//  lane a device initiated shared one key pair and a peer's reply burned keys the
//  server still served (A4FEDB36: sunflower's row 8CF55E2D cited it at 23:19:33Z,
//  the child's own lane B22CF8D3 at 23:21:05Z).
//

import BinaryCodable
import DoubleRatchetKit
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    private func header(of frame: ReceivedMessage) throws -> EncryptedHeader {
        try BinaryDecoder().decode(RatchetMessage.self, from: try #require(frame.message.signed).data).header
    }

    private func persisted(_ session: PQSSession, _ sharedId: String) async -> Bool {
        await pollUntil(timeout: 30) {
            (try? await session.cache?.fetchMessageIfExists(sharedId: sharedId)) != nil
        }
    }

    /// Alice opens a fresh lane toward bob and sends one frame on it, held in transit.
    private func heldFirstFrame(_ pair: ConnectedPair, consumingAKey: Bool = true) async throws -> ReceivedMessage {
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: consumingAKey,
            reason: "test")
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "first frame")
        #expect(await pollUntil(timeout: 20) { await held.count == 1 })
        pair.aliceTransport.shouldDeliver = nil
        return try #require(await held.take().first)
    }

    private func deliverToBob(_ pair: ConnectedPair, _ frame: ReceivedMessage) async {
        let accepted = await acceptedCount(pair.bob)
        pair.aliceTransport.continuation?.yield(frame)
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.bob) > accepted })
    }

    /// Alice's fresh lane reaches bob and his first reply on it is held in transit.
    private func heldFirstReply(
        _ pair: ConnectedPair
    ) async throws -> (frame: ReceivedMessage, initiatedRow: UUID, sharedId: String) {
        let first = try await heldFirstFrame(pair)
        let handshakeKey = try #require(try header(of: first).remoteOneTimePublicKey?.id)
        await deliverToBob(pair, first)

        let held = HeldFrames()
        pair.bobTransport.shouldDeliver = { received in
            guard received.recipient == "alice", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        let sharedId = "first-reply-\(UUID().uuidString)"
        try await pair.bob.send(recipient: .nickname("alice"), text: "first reply", sharedIdOverride: sharedId)
        #expect(await pollUntil(timeout: 20) { await held.count == 1 })
        pair.bobTransport.shouldDeliver = nil
        let reply = try #require(await held.take().first)
        #expect(try header(of: reply).oneTimeKeyId == handshakeKey, "the reply cites alice's handshake key")

        let initiated = try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId)
            .first { $0.stateOTK == handshakeKey }
        return (reply, try #require(initiated).id, sharedId)
    }

    @Test("two lanes from one device embed distinct handshake keys outside the published pool")
    func initiatedLanesEmbedDistinctKeysOutsideThePool() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }

        let first = try header(of: try await heldFirstFrame(pair))
        let second = try header(of: try await heldFirstFrame(pair))

        let firstKey = try #require(first.remoteOneTimePublicKey?.id)
        let secondKey = try #require(second.remoteOneTimePublicKey?.id)
        #expect(firstKey != secondKey, "each lane mints its own ephemeral")
        let context = try #require(await pair.alice.sessionContext)
        let pool = Set(context.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        let published = Set(context.activeUserConfiguration.signedOneTimePublicKeys.map(\.id))
        #expect(pool.isDisjoint(with: [firstKey, secondKey]), "the ephemeral never enters the pool")
        #expect(published.isDisjoint(with: [firstKey, secondKey]), "the ephemeral is never published")
        let finalKey = try await finalMLKEMKeyId(pair.alice)
        #expect(first.remoteMLKEMPublicKey.id == finalKey)
        #expect(second.remoteMLKEMPublicKey.id == finalKey)
        await pair.finish()
    }

    /// 9880E02D, 01:41:33Z: sunflower's receipt on an initiated lane left the child
    /// pending on A8563794/7DBDA71E, keys the server still served.
    @Test("a reply on an initiated lane leaves the published pool alone")
    func replyOnInitiatedLaneLeavesThePublishedPoolAlone() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let reply = try await heldFirstReply(pair)
        let before = try #require(await pair.alice.sessionContext)
        let uploads = await pair.aliceTransport.updateOneTimeKeysCallCount

        pair.bobTransport.continuation?.yield(reply.frame)
        #expect(await persisted(pair.alice, reply.sharedId))

        let after = try #require(await pair.alice.sessionContext)
        #expect(after.sessionUser.deviceKeys.pendingOneTimeKeyConsumptions == nil)
        #expect(after.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id)
            == before.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        #expect(after.activeUserConfiguration.signedOneTimePublicKeys.map(\.id)
            == before.activeUserConfiguration.signedOneTimePublicKeys.map(\.id))
        #expect(await pair.aliceTransport.updateOneTimeKeysCallCount == uploads)
        await pair.finish()
    }

    /// The owner's spend appended a replacement above the key it spent, and the
    /// server serves from the top, so the second consume reaches the spent key: the
    /// blank-only failure of 210AC674, not the every-row one.
    @Test("dogfood 2026-10-28: a key the server hands out survives the owner's own lanes")
    func servedKeySurvivesTheOwnersLanes() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        _ = try await store.fetchOneTimeKeys(for: "alice", deviceId: pair.aliceDeviceId.uuidString)
        _ = try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        let stats = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "on a served key")

        #expect(stats.winningLaneId != nil, "alice opens a frame citing a key the server served: \(stats.candidateOrder)")
        #expect(await pair.controls.reestablishments == 0, "no heal")
        await pair.finish()
    }

    /// The retirement gate drops the key from headers once both handshakes finish.
    /// Until then a lane embeds one id, across a relaunch and with no epoch re-key.
    @Test("a lane embeds one handshake key, then none, across traffic and a relaunch")
    func laneEmbedsOneHandshakeKeyThenNone() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let first = try await heldFirstFrame(pair)
        let captured = HeldFrames()
        pair.aliceTransport.transformOutgoing = { received in
            if received.recipient == "bob", received.isContentMessage { await captured.hold(received) }
            return received
        }
        await deliverToBob(pair, first)

        for round in 1...20 {
            _ = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "b\(round)")
            _ = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "a\(round)")
            if round == 10 {
                for row in try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId) {
                    await pair.alice.messagePipeline.ratchetManager.discardCachedLane(row.id)
                }
                for row in try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId) {
                    await pair.bob.messagePipeline.ratchetManager.discardCachedLane(row.id)
                }
            }
        }
        pair.aliceTransport.transformOutgoing = nil

        let headers = try ([first] + (await captured.take())).map { try header(of: $0) }
        let embedded = headers.map(\.remoteOneTimePublicKey?.id)
        let handshakeKey = try #require(embedded.first ?? nil)
        let citing = embedded.prefix { $0 != nil }
        #expect(citing.allSatisfy { $0 == handshakeKey }, "\(embedded)")
        #expect(embedded.dropFirst(citing.count).allSatisfy { $0 == nil }, "\(embedded)")
        #expect(citing.count < embedded.count, "both handshakes finished, so the key retired")
        #expect(Set(headers.map(\.ratchetEpochDigest)).count == 1, "no epoch re-key")
        #expect(await pair.controls.reestablishments == 0)
        await pair.finish()
    }

    /// A replay and a queued send can both reach a state-less row before either starts
    /// the handshake. A second key on that row reads to the ratchet as a local key change:
    /// an epoch before frame 0, which leaves bob a body he can't open on any row.
    @Test("every writer that reaches a state-less lane gets the lane's one ephemeral")
    func writersToAStatelessLaneShareOneEphemeral() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")

        let symmetricKey = try await pair.alice.getDatabaseSymmetricKey()
        var unstarted: (id: UUID, props: SessionIdentity.UnwrappedProps)?
        for row in try await #require(await pair.alice.cache).fetchSessionIdentities() {
            if let props = await row.props(symmetricKey: symmetricKey),
               props.deviceId == pair.bobDeviceId, !props.hasRatchetState, props.oneTimePublicKey != nil {
                unstarted = (row.id, props)
            }
        }
        let lane = try #require(unstarted)
        let context = try #require(await pair.alice.sessionContext)
        let first = try await pair.alice.messagePipeline.loadKeys(
            props: lane.props, sessionContext: context, session: pair.alice, laneId: lane.id)
        let second = try await pair.alice.messagePipeline.loadKeys(
            props: lane.props, sessionContext: context, session: pair.alice, laneId: lane.id)

        let ephemeral = try #require(first.localOneTimePrivateKey)
        #expect(second.localOneTimePrivateKey?.id == ephemeral.id)
        await pair.finish()
    }

    /// A row that consumed no key leaves the ephemeral nothing to agree with. Embedded
    /// anyway, it made bob's reply want a local key he could only mint, and a key new
    /// to an established lane is a re-key the peer mirrors only in order: every turn
    /// re-keyed, and a frame crossing one failed on every row.
    @Test("a lane that consumed no key keeps one epoch with its first reply crossing a frame")
    func laneWithoutAKeyKeepsOneEpochAcrossItsFirstReply() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let first = try await heldFirstFrame(pair, consumingAKey: false)
        #expect(try header(of: first).oneTimeKeyId == nil)
        #expect(try header(of: first).remoteOneTimePublicKey == nil, "the ephemeral would agree with nothing")
        _ = try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: false,
            reason: "test")
        await deliverToBob(pair, first)

        let toBob = HeldFrames()
        let toAlice = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await toBob.hold(received)
            return false
        }
        pair.bobTransport.shouldDeliver = { received in
            guard received.recipient == "alice", received.isContentMessage else { return true }
            await toAlice.hold(received)
            return false
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "second frame")
        try await pair.bob.send(recipient: .nickname("alice"), text: "first reply")
        #expect(await pollUntil(timeout: 20) { await toBob.count == 1 })
        #expect(await pollUntil(timeout: 20) { await toAlice.count == 1 })
        pair.aliceTransport.shouldDeliver = nil
        pair.bobTransport.shouldDeliver = nil
        let second = try #require(await toBob.take().first)
        let reply = try #require(await toAlice.take().first)

        let aliceBefore = await inboundCount(pair.alice)
        let bobBefore = await inboundCount(pair.bob)
        pair.aliceTransport.continuation?.yield(second)
        pair.bobTransport.continuation?.yield(reply)
        #expect(await pollUntil(timeout: 20) { await self.inboundCount(pair.bob) > bobBefore })
        #expect(await pollUntil(timeout: 20) { await self.inboundCount(pair.alice) > aliceBefore })

        for (session, before) in [(pair.alice, aliceBefore), (pair.bob, bobBefore)] {
            let stats = try #require(await session.messagePipeline.inboundLaneSelectionStatsLog.dropFirst(before).first)
            #expect(stats.winningLaneId != nil && stats.attempts.count == 1, "\(stats.candidateOrder)")
        }
        let headers = try [first, second, reply].map { try header(of: $0) }
        #expect(Set(headers.map(\.ratchetEpochDigest)).count == 1, "no epoch re-key")

        for (sender, recipient, receiver) in [(pair.alice, "bob", pair.bob), (pair.bob, "alice", pair.alice)] {
            let next = try await sendAndAwaitInbound(from: sender, to: recipient, on: receiver, text: "after the crossing")
            #expect(next.winningLaneId != nil && next.attempts.count == 1, "\(next.candidateOrder)")
        }
        #expect(await pair.controls.reestablishments == 0)
        await pair.finish()
    }

    /// Lookups by id found nothing to bind: a handshake key is not published, and the
    /// row's keys come from the frame's header.
    @Test("a peer row bootstrapped from a notify binds no curve key and the final ML-KEM key, and the reply works")
    func notifyBootstrappedRowBindsTheFinalKeyAndTheReplyWorks() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let first = try await heldFirstFrame(pair)

        // Bob meets alice's device afresh with a notify's key ids in the handshake
        // gate, naming keys alice did publish.
        let cache = try #require(await pair.bob.cache)
        for row in try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId) {
            try await cache.deleteSessionIdentity(row.id)
        }
        await pair.bob.invalidateSessionIdentityCache(secretName: "alice")
        let configuration = try await pair.bobTransport.findConfiguration(for: "alice")
        await pair.bob.setAddingContact(try BinaryEncoder().encode(SynchronizationKeyIdentities(
            senderX25519Id: try #require(configuration.signedOneTimePublicKeys.first?.id.uuidString),
            senderMLKEMId: try #require(configuration.signedMLKEMOneTimePublicKeys.first?.id.uuidString),
            recipientX25519Id: "",
            recipientMLKEMId: "")))

        let row = try #require(try await pair.bob.refreshIdentities(secretName: "alice").first)
        let props = try #require(await row.props(symmetricKey: try await pair.bob.getDatabaseSymmetricKey()))
        #expect(props.oneTimePublicKey == nil)
        #expect(props.mlKEMPublicKey.id == (try await finalMLKEMKeyId(pair.alice)))
        #expect(await pair.bob.addingContactData == nil, "the refresh lifts the handshake gate")

        await deliverToBob(pair, first)
        let reply = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "reply on the notify row")
        #expect(reply.winningLaneId != nil && reply.attempts.count == 1, "\(reply.candidateOrder)")
        await pair.finish()
    }

    /// A row goes at 40 stateful archives or 30 days. No pool key can open the reply,
    /// so the heal is the peer's refresh; it runs once, however many copies land.
    @Test("a reply whose initiating row was evicted costs one bounded heal")
    func evictedInitiatingRowCostsOneBoundedHeal() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let reply = try await heldFirstReply(pair)
        let cache = try #require(await pair.alice.cache)
        try await cache.deleteSessionIdentity(reply.initiatedRow)

        pair.bobTransport.continuation?.yield(reply.frame)
        #expect(await pollUntil(timeout: 30) { sink.contains("action=replaceOTKBatchThenPeerRefresh") },
                "\(sink.lines(containing: reply.frame.messageId))")
        pair.bobTransport.continuation?.yield(reply.frame)

        #expect(await persisted(pair.alice, reply.sharedId), "bob re-encrypts the reply once alice refreshed the lane")
        #expect(sink.lines(containing: "action=replaceOTKBatchThenPeerRefresh").count == 1)
        #expect(sink.lines(containing: "pqs.otk.batchReplaced kind=x25519 ").count == 1)
        await pair.finish()
    }

    @Test("the archived row that initiated a lane opens its first reply, with no heal")
    func archivedInitiatingRowOpensTheFirstReply() async throws {
        let sink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: sink)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let reply = try await heldFirstReply(pair)
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: false,
            reason: "test")
        let initiated = try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId)
            .first { $0.id == reply.initiatedRow }
        #expect(initiated?.archived == true)

        pair.bobTransport.continuation?.yield(reply.frame)

        #expect(await persisted(pair.alice, reply.sharedId))
        #expect(await pair.alice.messagePipeline.inboundLaneSelectionStatsLog.contains {
            $0.winningLaneId == reply.initiatedRow
        })
        #expect(!sink.contains("action=replaceOTKBatchThenPeerRefresh"))
        await pair.finish()
    }

    @Test("a first reply citing the final ML-KEM key opens from the row's copy after two rotations")
    func firstReplyOpensAcrossFinalKeyRotations() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let finalKey = try await finalMLKEMKeyId(pair.alice)
        let reply = try await heldFirstReply(pair)
        #expect(try header(of: reply.frame).mlKEMOneTimeKeyId == finalKey)

        for _ in 1...2 {
            try await makeRotationDue(on: pair.alice)
            #expect(try await pair.alice.rotateMLKEMKeysIfNeeded())
        }
        #expect(await pair.alice.sessionContext?.sessionUser.deviceKeys.finalMLKEMPrivateKey(matching: finalKey) == nil)

        pair.bobTransport.continuation?.yield(reply.frame)
        #expect(await persisted(pair.alice, reply.sharedId))
        await pair.finish()
    }
}
