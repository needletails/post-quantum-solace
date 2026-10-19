//
//  InterruptedSendQueueStallTests.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import Foundation
@testable import PQSSession
import Testing

/// A send interrupted by the background suspend, then retried around the
/// foreground reconnect, must not leave the job queue stopped while the
/// session is viable. Inbound decrypt and outbound sends share this queue,
/// so a stopped queue looks like the app has stopped sending and receiving.
@Suite(.serialized)
actor InterruptedSendQueueStallTests {

    var session = PQSSession()
    let transport: _MockTransportDelegate
    var receiver: ReceiverDelegate
    let store = TransportStore()

    init() {
        receiver = ReceiverDelegate(session: session)
        transport = _MockTransportDelegate(session: session, store: store)
    }

    private func createSession() async throws {
        let identityStore = MockIdentityStore(mockUserData: .init(session: session), session: session, isSender: true)
        await identityStore.setLocalSalt("testSalt1")
        await session.setDatabaseDelegate(conformer: identityStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: receiver)
        await session.setConnectivity(true)
        await store.setPublishableName("alice")
        session = try await session.createAccount(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.unlock(appPassword: "123")
        try await receiver.setKey(session.getDatabaseSymmetricKey())
    }

    /// Models: the media send is mid-flight when the app backgrounds; on
    /// foreground nudge-kit calls `resumeJobQueue()` after IRC registration
    /// while that send is still executing; the send then fails with a
    /// connectivity error (multipart leg not attached yet) and parks.
    @Test("A resume that lands while a send is executing is not lost when that send parks")
    func resumeDuringExecutingSendIsNotLost() async throws {
        try await createSession()
        let delegate = InterruptedSendDelegate(failingText: "media-A", holdFirstAttempt: true)
        await session.messagePipeline.setTaskDelegate(delegate)
        let recipient = makeRecipientIdentity()
        let mediaTask = makeWriteTask("media-A", sharedId: "shared-A", recipient: recipient)
        let textTask = makeWriteTask("text-B", sharedId: "shared-B", recipient: recipient)

        let draining = Task {
            try await self.session.messagePipeline.enqueue(mediaTask, session: self.session)
        }
        #expect(await delegate.gate.waitUntilHeld(timeout: 2), "media-A should be executing")

        try await session.messagePipeline.enqueue(textTask, session: session)
        try await session.resumeJobQueue()

        await delegate.gate.release()
        try await draining.value

        let drained = try await waitUntil(timeout: 3) {
            let processed = await delegate.processed()
            return processed.contains("media-A") && processed.contains("text-B")
        }
        let processed = await delegate.processed()
        let remaining = try await session.cache?.fetchJobs().count ?? -1
        #expect(
            drained,
            """
            BUG: the resume requested while media-A was executing was dropped. \
            Session is viable, yet the queue stopped. processed=\(processed) jobsLeftInCache=\(remaining)
            """)

        await session.shutdown()
    }

    /// Models: after the foreground resume, the first send fails with a
    /// connectivity error while its signed frame is still remembered in
    /// memory. That sets `isPausedUntilTransportReady`, and nothing on a
    /// connected session clears it, so later inbound and outbound jobs are
    /// persisted but never processed.
    @Test("A send that parks after the reconnect resume does not block later traffic on a viable session")
    func sendParkedAfterResumeDoesNotBlockLaterTraffic() async throws {
        try await createSession()
        let delegate = InterruptedSendDelegate(failingText: "media-A", holdFirstAttempt: false)
        await session.messagePipeline.setTaskDelegate(delegate)
        let recipient = makeRecipientIdentity()

        await session.messagePipeline.test_rememberPendingOutboundFrame(sharedId: "shared-A")
        try await session.messagePipeline.enqueue(
            makeWriteTask("media-A", sharedId: "shared-A", recipient: recipient),
            session: session)
        #expect(await delegate.failedAttempts() == 1, "media-A should have failed once and parked")

        let inbound = try makeInboundTaskMessage(sharedMessageId: "incoming-1")
        try await session.messagePipeline.inboundTask(inbound, session: session)
        try await session.messagePipeline.enqueue(
            makeWriteTask("text-B", sharedId: "shared-B", recipient: recipient),
            session: session)

        let flowedWhileConnected = try await waitUntil(timeout: 3) {
            let processed = await delegate.processed()
            return processed.contains("stream_incoming-1") && processed.contains("text-B")
        }
        let processedWhileConnected = await delegate.processed()
        let remaining = try await session.cache?.fetchJobs().count ?? -1
        #expect(
            flowedWhileConnected,
            """
            BUG: one parked send stopped all later inbound and outbound jobs on a viable session. \
            processed=\(processedWhileConnected) jobsLeftInCache=\(remaining)
            """)

        // Only another resume (the next IRC registration) frees the queue.
        try await session.resumeJobQueue()
        let drainedAfterResume = try await waitUntil(timeout: 3) {
            let processed = await delegate.processed()
            return processed.contains("stream_incoming-1") && processed.contains("text-B")
        }
        #expect(drainedAfterResume, "resumeJobQueue should drain the parked work")

        await session.shutdown()
    }

    /// Desired behavior for the whole incident: a send whose retries keep
    /// failing parks alone — inbound and other sends keep flowing with no
    /// resume needed — and after a bounded number of deferred retries it
    /// fails out visibly instead of livelocking until the user deletes it.
    ///
    /// Runs twice: with the signed frame remembered in memory (same process,
    /// within the 10-minute TTL) and without it (after an app relaunch, or
    /// once the TTL evicted it). Both must park per job and count toward the
    /// cap; the no-frame path used to fall through to a queue-wide pause.
    @Test(
        "A parked send never blocks other traffic, and its retries fail out after the cap",
        arguments: [true, false])
    func parkedSendDoesNotBlockTrafficAndFailsOutAfterCap(remembersFrame: Bool) async throws {
        try await createSession()
        let delegate = AlwaysFailingSendDelegate(failingText: "media-A")
        await session.messagePipeline.setTaskDelegate(delegate)
        let recipient = makeRecipientIdentity()

        if remembersFrame {
            // The frame was signed and remembered before transport, as in production.
            await session.messagePipeline.test_rememberPendingOutboundFrame(sharedId: "shared-A")
        }
        try await session.messagePipeline.enqueue(
            makeWriteTask("media-A", sharedId: "shared-A", recipient: recipient),
            session: session)
        let firstAttempts = await delegate.failedAttempts()
        #expect(firstAttempts == 1, "The interrupted send fails once and parks")

        // The incident assertion: with the send parked and NO resume event,
        // inbound decrypt and other sends keep flowing on the viable session.
        try await session.messagePipeline.inboundTask(
            makeInboundTaskMessage(sharedMessageId: "incoming-1"),
            session: session)
        try await session.messagePipeline.enqueue(
            makeWriteTask("text-B", sharedId: "shared-B", recipient: recipient),
            session: session)
        let flowedWithoutResume = try await waitUntil(timeout: 3) {
            let processed = await delegate.processed()
            return processed.contains("stream_incoming-1") && processed.contains("text-B")
        }
        let processedAlongsidePark = await delegate.processed()
        #expect(
            flowedWithoutResume,
            "A parked send must not block inbound or other sends: processed=\(processedAlongsidePark)")
        let parkedAttempts = await delegate.failedAttempts()
        #expect(parkedAttempts == 1, "Other traffic must not tight-retry the parked send")

        // Each reconnect resume retries the parked send once. After the cap,
        // the job fails out and is removed instead of parking forever.
        for _ in 0..<15 {
            try await session.resumeJobQueue()
            if try await poisonJobCount(sharedId: "shared-A") == 0 { break }
        }
        let jobsLeft = try await poisonJobCount(sharedId: "shared-A")
        let totalAttempts = await delegate.failedAttempts()
        #expect(
            jobsLeft == 0,
            "A send that keeps failing at every resume must fail out, not retry forever (attempts=\(totalAttempts))")
        #expect(totalAttempts <= 12, "Retries must be bounded by the cap")

        // With the poison gone, the queue needs no resume to keep working.
        try await session.messagePipeline.enqueue(
            makeWriteTask("text-C", sharedId: "shared-C", recipient: recipient),
            session: session)
        let textCFlowed = try await waitUntil(timeout: 3) {
            await delegate.processed().contains("text-C")
        }
        #expect(textCFlowed, "After the fail-out, new sends flow without a resume")

        await session.shutdown()
    }

    private func poisonJobCount(sharedId: String) async throws -> Int {
        guard let cache = await session.cache else { return 0 }
        let key = try await session.getDatabaseSymmetricKey()
        var count = 0
        for job in try await cache.fetchJobs() {
            guard let props = await job.props(symmetricKey: key),
                  case .writeMessage(let outbound) = props.task.task,
                  outbound.sharedId == sharedId
            else { continue }
            count += 1
        }
        return count
    }

    // MARK: - Helpers

    private func makeRecipientIdentity() -> SessionIdentity {
        let id = UUID()
        return try! SessionIdentity(
            id: id,
            props: .init(
                secretName: "bob",
                deviceId: id,
                sessionContextId: 0,
                longTermPublicKey: .init(),
                signingPublicKey: .init(),
                mlKEMPublicKey: .init(.init(count: 1568)),
                oneTimePublicKey: nil,
                deviceName: "bob-device",
                isMasterDevice: true),
            symmetricKey: .init(size: .bits256))
    }

    private func makeWriteTask(_ text: String, sharedId: String, recipient: SessionIdentity) -> EncryptableTask {
        EncryptableTask(
            task: .writeMessage(.init(
                message: CryptoMessage(
                    text: text,
                    metadata: .init(),
                    recipient: .nickname("bob"),
                    sentDate: Date(),
                    destructionTime: nil),
                recipientIdentity: recipient,
                localId: UUID(),
                sharedId: sharedId)),
            priority: .urgent)
    }

    private func makeInboundTaskMessage(sharedMessageId: String) throws -> InboundTaskMessage {
        let header = EncryptedHeader(
            remoteLongTermPublicKey: Data(repeating: 1, count: 32),
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: try MLKEMPublicKey(Data(repeating: 2, count: 1568)),
            headerCiphertext: Data([0x01]),
            messageCiphertext: Data([0x02]),
            oneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID(),
            encrypted: Data([0x04]))
        let signed = try SignedRatchetMessage(
            message: RatchetMessage(header: header, ciphertext: Data([0x03])),
            signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation)
        return InboundTaskMessage(
            message: signed,
            senderSecretName: "bob",
            senderDeviceId: UUID(),
            sharedMessageId: sharedMessageId,
            logicalSharedId: sharedMessageId)
    }

    private func waitUntil(
        timeout: TimeInterval,
        _ condition: @escaping @Sendable () async -> Bool
    ) async throws -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await condition() { return true }
            try await Task.sleep(until: .now + .milliseconds(50))
        }
        return await condition()
    }
}

// MARK: - Fakes

/// Fails the first attempt of `failingText` with a connectivity error, the way
/// a send fails when the IRC or multipart writer is gone. With
/// `holdFirstAttempt`, that attempt waits on `gate` first so the test can act
/// while it is executing.
private final class InterruptedSendDelegate: TaskSequenceDelegate, @unchecked Sendable {
    let gate = ExecutingSendGate()
    private let failingText: String
    private let holdFirstAttempt: Bool
    private let tracker = MessageTracker()
    private let failures = ErrorTracker()

    init(failingText: String, holdFirstAttempt: Bool) {
        self.failingText = failingText
        self.holdFirstAttempt = holdFirstAttempt
    }

    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        switch task {
        case .writeMessage(let outbound):
            if outbound.message.text == failingText, await failures.getErrorCount() == 0 {
                await failures.incrementErrorCount()
                if holdFirstAttempt {
                    await gate.hold()
                }
                throw PQSError.connectionIsNonViable
            }
            await tracker.addMessage(outbound.message.text)
        case .streamMessage(let inbound):
            await tracker.addMessage("stream_\(inbound.sharedMessageId)")
        }
    }

    func processed() async -> [String] {
        await tracker.getMessages()
    }

    func failedAttempts() async -> Int {
        await failures.getErrorCount()
    }
}

/// Fails every attempt of `failingText` with a connectivity-shaped error;
/// processes everything else. Models a send whose retries only ever run at
/// reconnect moments, when the leg it needs is not up yet.
private final class AlwaysFailingSendDelegate: TaskSequenceDelegate, @unchecked Sendable {
    private let failingText: String
    private let tracker = MessageTracker()
    private let failures = ErrorTracker()

    init(failingText: String) {
        self.failingText = failingText
    }

    func performRatchet(task: SessionModels.TaskType, session: PQSSession) async throws {
        switch task {
        case .writeMessage(let outbound):
            if outbound.message.text == failingText {
                await failures.incrementErrorCount()
                throw PQSError.connectionIsNonViable
            }
            await tracker.addMessage(outbound.message.text)
        case .streamMessage(let inbound):
            await tracker.addMessage("stream_\(inbound.sharedMessageId)")
        }
    }

    func processed() async -> [String] {
        await tracker.getMessages()
    }

    func failedAttempts() async -> Int {
        await failures.getErrorCount()
    }
}

private actor ExecutingSendGate {
    private var isHeld = false
    private var continuation: CheckedContinuation<Void, Never>?

    func hold() async {
        isHeld = true
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func waitUntilHeld(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if isHeld, continuation != nil { return true }
            try? await Task.sleep(until: .now + .milliseconds(20))
        }
        return isHeld && continuation != nil
    }

    func release() {
        continuation?.resume()
        continuation = nil
    }
}

extension MessagePipeline {
    /// Test-only: stands in for the signed frame the first encrypt attempt
    /// remembers before handing it to transport.
    func test_rememberPendingOutboundFrame(sharedId: String) {
        rememberPendingOutboundTransport(
            sharedId: sharedId,
            message: SignedRatchetMessage(outOfBandPlaceholder: ()),
            metadata: SignedRatchetMessageMetadata(
                secretName: "bob",
                deviceId: UUID(),
                recipient: .nickname("bob"),
                transportMetadata: nil,
                sharedMessageId: sharedId,
                envelopeMessageId: UUID().uuidString,
                transportEvent: nil),
            sessionIdentityId: UUID(),
            needsRemoteDeletion: false,
            x25519OneTimeKeyId: nil,
            mlKEMOneTimeKeyId: UUID().uuidString)
    }
}
