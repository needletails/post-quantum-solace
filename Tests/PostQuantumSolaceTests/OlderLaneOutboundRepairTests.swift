//
//  OlderLaneOutboundRepairTests.swift
//  post-quantum-solace
//
//  A lane left by an older build holds a peer key, no local key and an unfinished
//  send handshake, so strict encrypt throws `missingOneTimeKey` on the first send.
//  That send worked before strict encrypt, with no directory and whatever the peer
//  had in flight, so its repair has to work under the same conditions.
//

import Crypto
@testable import DoubleRatchetKit
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

/// Runs the real ratchet. Before the first attempt at `sharedId`, runs `beforeSend`.
private final class FrameDuringSendDelegate: TaskSequenceDelegate, @unchecked Sendable {
    private actor Attempts {
        var count = 0
        func next() -> Int {
            count += 1
            return count
        }
    }

    private let attempts = Attempts()
    private let sharedId: String
    private let beforeSend: @Sendable () async -> Void

    init(sharedId: String, beforeSend: @escaping @Sendable () async -> Void) {
        self.sharedId = sharedId
        self.beforeSend = beforeSend
    }

    func performRatchet(task: TaskType, session: PQSSession) async throws {
        if case .writeMessage(let message) = task, message.sharedId == sharedId,
           await attempts.next() == 1 {
            await beforeSend()
        }
        try await session.messagePipeline.performRatchet(task: task, session: session)
    }

    var attemptCount: Int {
        get async { await attempts.count }
    }
}

extension EndToEndTests {
    private func updateActiveLaneState(
        on session: PQSSession,
        peer: String,
        deviceId: UUID,
        _ change: (RatchetState) async -> RatchetState
    ) async throws {
        let cache = try #require(await session.cache)
        let key = try await session.getDatabaseSymmetricKey()
        for identity in try await cache.fetchSessionIdentities() {
            guard var props = await identity.props(symmetricKey: key),
                  props.secretName == peer,
                  props.deviceId == deviceId,
                  !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix),
                  let state = props.state
            else { continue }
            props.state = await change(state)
            try await identity.update(props, symmetricKey: key)
            try await cache.updateSessionIdentity(identity)
            await session.messagePipeline.ratchetManager.discardCachedLane(identity.id)
            return
        }
        Issue.record("no active lane toward \(peer)")
    }

    /// Bob opens a lane the way an older build did: bob embeds an ephemeral that
    /// agreed with nothing, and alice stored it as the peer's key.
    private func olderBuildLane(_ pair: ConnectedPair) async throws {
        _ = try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: false,
            reason: "test")
        let stats = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "from an older build")
        #expect(stats.winningLaneId != nil, "\(stats.candidateOrder)")

        // Alice can open the frame before bob's send has committed the lane.
        #expect(await pollUntil(timeout: 10) {
            (try? await pair.bob.cache?.fetchJobs().isEmpty) == true
        })

        let keyPair = Curve25519.KeyAgreement.PrivateKey()
        let ephemeral = try X25519PrivateKey(keyPair.rawRepresentation)
        let embedded = try X25519PublicKey(id: ephemeral.id, keyPair.publicKey.rawRepresentation)
        try await updateActiveLaneState(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId) {
            await $0.updateLocalOneTimePrivateKey(ephemeral)
        }
        try await updateActiveLaneState(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId) {
            await $0.updateRemoteOneTimePublicKey(embedded)
        }
    }

    private func arrives(_ sharedId: String, on session: PQSSession) async -> Bool {
        await pollUntil(timeout: 20) {
            (try? await session.cache?.fetchMessageIfExists(sharedId: sharedId)) != nil
        }
    }

    @Test("a send on an older lane leaves while directory lookups time out")
    func olderLaneSendSurvivesDirectoryTimeouts() async throws {
        let probe = OutboundUnrecoverableProbe()
        let pair = try await connectedPair(aliceUnrecoverableProbe: probe)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        try await olderBuildLane(pair)

        pair.aliceTransport.findConfigurationError = URLError(.timedOut)
        pair.aliceTransport.findConfigurationFaultSecretNames = ["bob"]
        let sharedId = UUID().uuidString
        try await pair.alice.send(recipient: .nickname("bob"), text: "sent while lookups time out", sharedIdOverride: sharedId)

        #expect(await arrives(sharedId, on: pair.bob), "the message left alice")
        let unrecoverable = await probe.recorded()
        #expect(unrecoverable.isEmpty, "\(unrecoverable)")
        await pair.finish()
    }

    @Test("a repaired send survives a frame that promotes the old lane over the new row")
    func repairedSendSurvivesCrossingPromotion() async throws {
        let probe = OutboundUnrecoverableProbe()
        let pair = try await connectedPair(aliceUnrecoverableProbe: probe)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        try await olderBuildLane(pair)

        // Bob's next frame on that lane is in flight when alice answers.
        let held = HeldFrames()
        pair.bobTransport.shouldDeliver = { received in
            guard received.recipient == "alice", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        try await pair.bob.send(recipient: .nickname("alice"), text: "crossing frame")
        #expect(await pollUntil(timeout: 20) { await held.count >= 1 })
        pair.bobTransport.shouldDeliver = nil
        let crossing = try #require(await held.take().first)

        // Jobs run one at a time, so a frame queued during the send runs before its retry.
        let sharedId = UUID().uuidString
        let bobTransport = pair.bobTransport
        let alice = pair.alice
        let delegate = FrameDuringSendDelegate(sharedId: sharedId) {
            bobTransport.continuation?.yield(crossing)
            _ = await self.pollUntil(timeout: 10) {
                (try? await alice.cache?.fetchJobs().count) ?? 0 > 1
            }
        }
        await alice.messagePipeline.setTaskDelegate(delegate)
        try await alice.send(recipient: .nickname("bob"), text: "alice answers", sharedIdOverride: sharedId)

        #expect(await arrives(sharedId, on: pair.bob), "the message left alice")
        #expect(await delegate.attemptCount == 3, "the frame promoted the old lane, so the first retry failed there")
        let unrecoverable = await probe.recorded()
        #expect(unrecoverable.isEmpty, "\(unrecoverable)")
        await pair.finish()
    }
}
