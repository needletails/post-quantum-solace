//
//  ColdJobListRelaunchTests.swift
//  post-quantum-solace
//
//  A message composed offline is a persisted job, and the next launch sends it once the
//  transport is viable, oldest first. The cache reads its job list from the store only
//  while that list is empty. A message composed after a relaunch but before anything read
//  the jobs made the list non-empty with that one job, so the resume saw only it: the new
//  message went out first and the one from the previous run waited until the list emptied.
//
//  Real pieces: Alice's session, store, job queue, send path and resume on viability, and
//  Bob really decrypting what is routed. The relaunch is a new PQSSession unlocked over the
//  store the first one wrote, as the next process does. Double: the transport.
//

import Foundation
import Testing
@testable import PQSSession
import SessionModels

extension EndToEndTests {
    /// Runs the relaunch and returns the order in which the two messages reached the
    /// transport: `previous` was composed offline before the relaunch, `current` after it.
    private func sendOrderAfterRelaunch(
        loadJobsBeforeCompose: Bool
    ) async throws -> (order: [String], previous: String, current: String) {
        let aliceStore = createSenderStore()
        await aliceStore.setDetachesRows(true)
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let aliceDelegate = SessionDelegate(session: _senderSession)
        let bobDelegate = SessionDelegate(session: _recipientSession)
        try await createSenderSession(store: aliceStore, transport: aliceTransport, sessionDelegate: aliceDelegate)
        try await createRecipientSession(store: createRecipientStore(), transport: bobTransport, sessionDelegate: bobDelegate)
        try await createFriendship(aliceSession: _senderSession, sd: aliceDelegate, bobSession: _recipientSession, rsd: bobDelegate)

        let (toBob, bobInbox) = AsyncStream<ReceivedMessage>.makeStream()
        aliceTransport.continuation = bobInbox
        let bobTask = Task {
            for await received in toBob where received.recipient == "bob" {
                _ = try? await self.receiveIgnoringRecoverableErrors(self._recipientSession, received: received)
            }
        }
        defer { bobTask.cancel() }
        func bobHas(_ sharedId: String) async -> Bool {
            await pollUntil(timeout: 10) {
                (try? await self._recipientSession.cache?.fetchMessageIfExists(sharedId: sharedId)) != nil
            }
        }

        // The lane is established while online.
        let warm = "warm-\(UUID().uuidString)"
        try await _senderSession.send(recipient: .nickname("bob"), text: "warm", sharedIdOverride: warm)
        await _senderSession.waitForOutboundJobDrain()
        try #require(await bobHas(warm), "setup: Bob decrypts the first message")

        // Previous run: offline, the user sends a message, then the process ends.
        await _senderSession.setConnectivity(false)
        let previous = "previous-\(UUID().uuidString)"
        try await _senderSession.send(recipient: .nickname("bob"), text: "previous", sharedIdOverride: previous)
        let key = try await _senderSession.getDatabaseSymmetricKey()
        func storedJobIds(_ sharedId: String) async -> [UUID] {
            var ids: [UUID] = []
            for job in await aliceStore.persistedJobs {
                guard let props = await job.props(symmetricKey: key),
                      case .writeMessage(let outbound) = props.task.task,
                      outbound.sharedId == sharedId else { continue }
                ids.append(job.id)
            }
            return ids
        }
        try #require(await !storedJobIds(previous).isEmpty, "setup: the offline message is a persisted job")
        await _senderSession.shutdown()

        // Relaunch: a new process unlocks over the same store, still offline.
        var relaunched = PQSSession()
        let relaunchedTransport = _MockTransportDelegate(session: relaunched, store: store)
        relaunchedTransport.continuation = bobInbox
        let relaunchedReceiver = ReceiverDelegate(session: relaunched)
        await relaunched.setDatabaseDelegate(conformer: aliceStore)
        await relaunched.setTransportDelegate(conformer: relaunchedTransport)
        await relaunched.setPQSSessionDelegate(conformer: SessionDelegate(session: relaunched))
        await relaunched.setReceiverDelegate(conformer: relaunchedReceiver)
        await relaunched.setAppPassword(sMockUserData.sap)
        relaunched = try await relaunched.unlock(appPassword: sMockUserData.sap)
        try await relaunchedReceiver.setKey(relaunched.getDatabaseSymmetricKey())
        // The mock never confirms a server accept; keep resends out of the order.
        await relaunched.messagePipeline.testSetAckDeadlineNanosecondsForTests(3_600_000_000_000)
        let log = SentEnvelopeLog()
        relaunchedTransport.duringSendMessage = { received in await log.record(received) }

        if loadJobsBeforeCompose {
            _ = try await relaunched.cache?.fetchJobs()
        }

        // The user sends again before the connection is back.
        let current = "current-\(UUID().uuidString)"
        try await relaunched.send(recipient: .nickname("bob"), text: "current", sharedIdOverride: current)
        try #require(await !storedJobIds(current).isEmpty, "setup: the new message is a persisted job")
        try #require(await log.count() == 0, "setup: nothing is sent while offline")

        // The connection comes back; viability resumes the job queue.
        await relaunched.setConnectivity(true)
        #expect(await bobHas(previous), "the message from the previous run reaches Bob")
        #expect(await bobHas(current), "the new message reaches Bob")
        await jobLoopIdle(relaunched)

        var order: [String] = []
        for frame in await log.sent where frame.recipient == "bob" {
            guard let id = frame.logicalMessageId, [previous, current].contains(id), !order.contains(id) else { continue }
            order.append(id)
        }
        await relaunched.shutdown()
        return (order, previous, current)
    }

    @Test("after a relaunch, a message composed offline in the previous run is sent before one composed since")
    func previousRunJobIsSentFirstAfterRelaunch() async throws {
        defer { Task { await shutdownSessions() } }
        let run = try await sendOrderAfterRelaunch(loadJobsBeforeCompose: false)
        #expect(run.order == [run.previous, run.current],
                "oldest first: \(run.order == [run.current, run.previous] ? "the new message went first" : "\(run.order)")")
    }

    @Test("Control: with the job list read before the compose, the previous run's message is sent first")
    func previousRunJobIsSentFirstWhenJobsWereRead() async throws {
        defer { Task { await shutdownSessions() } }
        let run = try await sendOrderAfterRelaunch(loadJobsBeforeCompose: true)
        #expect(run.order == [run.previous, run.current], "order \(run.order)")
    }
}
