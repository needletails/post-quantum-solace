//
//  MissedResumeStallTests.swift
//  post-quantum-solace
//
//  A send that fails at the transport pauses the job queue until the host resumes it after
//  the next registration. When that resume arrives while the send is still in flight (the
//  socket died under it and the host has already registered again), the queue is busy and
//  the resume starts nothing; the send then fails and pauses the queue with no resume left
//  to come. Inbound decrypts share that queue, so nothing is sent or shown until the next
//  reconnect.
//
//  Real pieces: connected PQSSessions, the sender's real job queue, send path and pause
//  logic, and the recipient really decrypting what is routed. Double: the transport, which
//  fails one send the way a closed socket does.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

private actor OnceFlag {
    private var used = false
    func first() -> Bool {
        if used { return false }
        used = true
        return true
    }
}

private struct ClosedChannelError: Error {}

extension EndToEndTests {

    @Test("A send that fails after a resume arrived during it does not stall the queue")
    func sendFailingAfterAResumeDuringItDoesNotStallTheQueue() async throws {
        let pair = try await connectedPair()
        let alice = pair.alice
        await alice.waitForOutboundJobDrain()
        await jobLoopIdle(alice)
        await jobLoopIdle(pair.bob)

        let sharedId = "missed-resume-\(UUID().uuidString)"
        let once = OnceFlag()
        pair.aliceTransport.duringSendMessage = { frame in
            guard frame.logicalMessageId == sharedId, await once.first() else { return }
            // The host registered again while this send was still on the dead socket...
            try await alice.resumeJobQueue()
            // ...and then the send fails.
            throw ClosedChannelError()
        }

        try await alice.send(recipient: .nickname("bob"), text: "after the drop", sharedIdOverride: sharedId)
        let delivered = await persisted(pair.bob, sharedId, timeout: 10)
        #expect(delivered, "the failed send must be retried without waiting for another reconnect")

        // Inbound work shares the queue: a message from Bob must still be handled.
        let reply = "missed-resume-reply-\(UUID().uuidString)"
        try await pair.bob.send(recipient: .nickname("alice"), text: "reply", sharedIdOverride: reply)
        let received = await persisted(alice, reply, timeout: 10)
        #expect(received, "inbound messages must still be handled")

        await pair.finish()
        await shutdownSessions()
    }

    @Test("Control: a send that fails with no resume during it waits for the next resume")
    func sendFailingWithNoResumeWaitsForTheNextResume() async throws {
        let pair = try await connectedPair()
        let alice = pair.alice
        await alice.waitForOutboundJobDrain()
        await jobLoopIdle(alice)
        await jobLoopIdle(pair.bob)

        let sharedId = "paused-send-\(UUID().uuidString)"
        let once = OnceFlag()
        pair.aliceTransport.duringSendMessage = { frame in
            guard frame.logicalMessageId == sharedId, await once.first() else { return }
            throw ClosedChannelError()
        }

        try await alice.send(recipient: .nickname("bob"), text: "paused", sharedIdOverride: sharedId)
        let early = await persisted(pair.bob, sharedId, timeout: 3)
        #expect(!early, "with no resume the failed send stays parked")
        try #require(await alice.messagePipeline.isPausedUntilTransportReady, "setup: the queue is paused")

        try await alice.resumeJobQueue()
        let delivered = await persisted(pair.bob, sharedId, timeout: 10)
        #expect(delivered, "the next resume sends it")

        await pair.finish()
        await shutdownSessions()
    }
}
