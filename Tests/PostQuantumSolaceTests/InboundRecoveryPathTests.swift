//
//  InboundRecoveryPathTests.swift
//  post-quantum-solace
//
//  The receiver's side of recovery, pinned against dogfood 2026-10-28 (the Mac
//  child lost one channel message and received another 59 minutes late): the
//  archive pass runs before any resend request leaves, an initiating frame
//  opens its lane whatever its position in the sender's chain, and a copy of
//  content this device already holds settles the resend requests pending for it.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    private func persisted(_ session: PQSSession, _ sharedId: String, timeout: TimeInterval = 20) async -> Bool {
        await pollUntil(timeout: timeout) {
            (try? await session.cache?.fetchMessageIfExists(sharedId: sharedId)) != nil
        }
    }

    private func identity(on session: PQSSession, id: UUID) async throws -> SessionIdentity {
        let cache = try #require(await session.cache)
        return try #require(try await cache.fetchSessionIdentities().first { $0.id == id })
    }

    @Test("a frame only an archived lane can decrypt is not NACKed before the archive pass has run")
    func archivePassRunsBeforeAnyResendRequest() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        // Bob archived the lane alice is sending on and holds a fresh state-less
        // row toward her: a remint on his side, as the child's at 02:10:03Z.
        let bobRow = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first)
        _ = try await pair.bob.demoteActiveSessionIdentityToInactive(try await identity(on: pair.bob, id: bobRow.id))
        _ = try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: false,
            reason: "test",
            demotePriorActives: false)

        let sharedId = "archived-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "still on the old lane", sharedIdOverride: sharedId)

        #expect(await persisted(pair.bob, sharedId), "the archived lane decrypts the frame in the background pass")
        #expect(await pair.bob.messagePipeline.inboundLaneSelectionStatsLog.contains {
            $0.pass == .archived && $0.winningLaneId == bobRow.id
        }, "the archive pass, not the active-first pass, decrypted it")
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0,
                "no resend request may leave before the archive pass has had its say")
        #expect(await pair.bob.resendRequestSubmissionCount(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId) == 0)
        await pair.finish()
    }

    @Test("an initiating frame opens its lane even when the sender's first frame never arrived")
    func midChainInitiatingFrameOpensTheLane() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        // Alice starts a fresh lane toward bob (her remint); bob still holds the
        // old stateful lane. Her first frame on the new lane is lost in transit.
        _ = try await pair.alice.resetSessionIdentityForFreshSession(
            secretName: "bob",
            deviceId: pair.bobDeviceId,
            sendOneTimeIdentities: true,
            reason: "test")
        let held = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
        let lost = "lost-first-\(UUID().uuidString)"
        let second = "second-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "first, lost", sharedIdOverride: lost)
        try await pair.alice.send(recipient: .nickname("bob"), text: "second, arrives", sharedIdOverride: second)
        #expect(await pollUntil(timeout: 20) { await held.count == 2 })
        pair.aliceTransport.shouldDeliver = nil
        let frames = await held.take()
        pair.aliceTransport.continuation?.yield(frames[1])

        #expect(await persisted(pair.bob, second),
                "bob's blank decrypted this frame from its header; the plaintext must reach the user, not be refused as mid-session")
        #expect(await pair.bobTransport.outOfBandResendRequestCount == 0, "nothing to ask the sender for")
        await pair.finish()
    }

    @Test("a copy of content this device already holds settles the resend requests pending for it")
    func duplicateOfPersistedContentSettlesPendingResend() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        let sharedId = "held-\(UUID().uuidString)"
        let captured = HeldFrames()
        pair.aliceTransport.transformOutgoing = { received in
            if received.logicalMessageId == sharedId { await captured.hold(received) }
            return received
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "content", sharedIdOverride: sharedId)
        #expect(await persisted(pair.bob, sharedId))
        pair.aliceTransport.transformOutgoing = nil
        let original = try #require(await captured.take().first)

        // A host re-arm (a relaunch with a stale placeholder ledger) left a NACK
        // pending for content bob already has, as the master's did for C653BE44.
        await pair.bob.deferPeerResendUntilReestablished(
            sender: "alice",
            deviceId: pair.aliceDeviceId,
            failedMessageId: sharedId,
            failureClass: "hostRearm",
            notifyDelegate: false)
        #expect(await pair.bob.hasPendingResendAfterReestablishment(
            sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId))

        // The sender answers with the same frame under a fresh envelope id.
        pair.aliceTransport.continuation?.yield(ReceivedMessage(
            message: original.message,
            sender: original.sender,
            recipient: original.recipient,
            deviceId: original.deviceId,
            recipientDeviceId: original.recipientDeviceId,
            messageId: UUID().uuidString,
            logicalMessageId: sharedId,
            transportEvent: original.transportEvent))
        #expect(await pollUntil(timeout: 20) {
            await !pair.bob.hasPendingResendAfterReestablishment(
                sender: "alice", deviceId: pair.aliceDeviceId, failedMessageId: sharedId)
        }, "the duplicate is dropped as already held and settles the pending resend")
        await pair.finish()
    }
}
