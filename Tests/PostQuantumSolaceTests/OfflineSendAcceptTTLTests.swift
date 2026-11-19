//
//  OfflineSendAcceptTTLTests.swift
//  post-quantum-solace
//
//  A send that fails at the transport keeps its encrypted envelope with its job, and the same
//  ciphertext goes out when the host resumes the queue after the next registration. The
//  accept ledger forgets an envelope ten minutes after it was tracked and fails its message.
//  That wait is for the server's accept, so it must count from the send that reached the
//  server, not from the encryption: a message composed on a dead connection more than ten
//  minutes before the reconnect must still move past sending when the server accepts it,
//  also when the next queued message is tracked before that accept arrives.
//
//  Real pieces: connected PQSSessions, the sender's real job queue, encryption, pause on a
//  failed send, resume, accept ledger and store rows, through the calls the host makes
//  (`send`, `resumeJobQueue`, `resendUnackedOutboundEnvelopes`, `confirmServerAcceptedEnvelope`).
//  Doubles: the transport, which fails sends the way a closed socket does and then keeps the
//  two test messages as a server does for an offline recipient, and the passing of time,
//  which the test applies by moving the kept envelope's creation time back in its stored job.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

private struct ClosedSocketError: Error {}

/// The envelope under which each test message reached the server.
private actor ServerInbox {
    private var envelopes: [String: String] = [:]
    func keep(_ sharedId: String, envelope: String) { envelopes[sharedId] = envelope }
    func envelope(of sharedId: String) -> String? { envelopes[sharedId] }
}

extension EndToEndTests {
    /// Alice sends `first` on a dead socket (it is encrypted, the send fails, the queue
    /// pauses) and then `second`. `offline` seconds pass. The connection comes back and the
    /// host resumes the queue and replays unaccepted envelopes, as nudge-kit does on a
    /// registration. Then the server accepts `first`. Returns the stored state of `first`.
    func stateOfMessageComposedOnADeadConnection(reconnectingAfter offline: TimeInterval) async throws -> DeliveryState? {
        let pair = try await connectedPair()
        let alice = pair.alice
        // As the app's store: a state only reaches the store through a store write.
        await pair.aliceStore.setReturnsFreshMessageRows(true)
        await alice.waitForOutboundJobDrain()
        await jobLoopIdle(alice)
        await jobLoopIdle(pair.bob)
        // Setup traffic went out before this test's server existed; a live server accepted it.
        for id in await Array(alice.messagePipeline.unackedServerAcceptByEnvelopeId.keys) {
            await alice.confirmServerAcceptedEnvelope(id)
        }

        let first = "dead-connection-first-\(UUID().uuidString)"
        let second = "dead-connection-second-\(UUID().uuidString)"
        let server = ServerInbox()
        pair.aliceTransport.shouldDeliver = { frame in
            guard frame.isContentMessage, let sharedId = frame.logicalMessageId, [first, second].contains(sharedId) else {
                return true
            }
            await server.keep(sharedId, envelope: frame.messageId)
            return false
        }

        pair.aliceTransport.sendMessageError = ClosedSocketError()
        try await alice.send(recipient: .nickname("bob"), text: "first", sharedIdOverride: first)
        let paused = await pollUntil(timeout: 10) { await alice.messagePipeline.isPausedUntilTransportReady }
        try #require(paused, "setup: the failed send paused the queue")
        await jobLoopIdle(alice)
        try await alice.send(recipient: .nickname("bob"), text: "second", sharedIdOverride: second)

        // Time passes: the envelope kept with the first message's job was made `offline` ago.
        let key = try await alice.getDatabaseSymmetricKey()
        var keptEnvelope = false
        for job in await pair.aliceStore.persistedJobs {
            guard var props = await job.props(symmetricKey: key),
                  case .writeMessage(let outbound) = props.task.task, outbound.sharedId == first,
                  let kept = props.preparedOutbound else { continue }
            props.preparedOutbound = JobModel.PreparedOutbound(
                signedMessage: kept.signedMessage,
                secretName: kept.secretName,
                deviceId: kept.deviceId,
                recipient: kept.recipient,
                transportMetadata: kept.transportMetadata,
                sharedMessageId: kept.sharedMessageId,
                envelopeMessageId: kept.envelopeMessageId,
                transportEvent: kept.transportEvent,
                requiresServerAck: kept.requiresServerAck,
                sessionIdentityId: kept.sessionIdentityId,
                x25519OneTimeKeyId: kept.x25519OneTimeKeyId,
                mlKEMOneTimeKeyId: kept.mlKEMOneTimeKeyId,
                createdAt: kept.createdAt.addingTimeInterval(-offline))
            _ = try await job.updateProps(symmetricKey: key, props: props)
            try await pair.aliceStore.updateJob(job)
            keptEnvelope = true
        }
        try #require(keptEnvelope, "setup: the first message's job kept its encrypted envelope")
        try #require(await server.envelope(of: first) == nil, "setup: nothing reached the server yet")

        // The connection is back.
        pair.aliceTransport.sendMessageError = nil
        try await alice.resumeJobQueue()
        await alice.resendUnackedOutboundEnvelopes(reason: "IRC registered")
        let bothSent = await pollUntil(timeout: 30) {
            let firstSent = await server.envelope(of: first) != nil
            let secondSent = await server.envelope(of: second) != nil
            return firstSent && secondSent
        }
        try #require(bothSent, "setup: both messages reached the server after the reconnect")
        await alice.waitForOutboundJobDrain()
        await jobLoopIdle(alice)

        // The server's accept for the first message arrives.
        let envelope = try #require(await server.envelope(of: first))
        await alice.confirmServerAcceptedEnvelope(envelope)
        let row = try #require(try await pair.aliceStore.fetchMessageIfExists(sharedId: first))
        let observed = await row.props(symmetricKey: key)?.deliveryState

        await pair.finish()
        await shutdownSessions()
        return observed
    }

    @Test("A message composed on a dead connection over ten minutes before the reconnect is sent, not failed")
    func messageComposedLongBeforeReconnectIsAccepted() async throws {
        let observed = try await stateOfMessageComposedOnADeadConnection(reconnectingAfter: 11 * 60)
        #expect(observed == .waitingDelivery, "the server accepted the message: observed \(String(describing: observed))")
    }

    @Test("Control: a message composed on a dead connection under ten minutes before the reconnect is sent")
    func messageComposedShortlyBeforeReconnectIsAccepted() async throws {
        let observed = try await stateOfMessageComposedOnADeadConnection(reconnectingAfter: 9 * 60)
        #expect(observed == .waitingDelivery, "the server accepted the message: observed \(String(describing: observed))")
    }
}
