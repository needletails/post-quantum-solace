//
//  OutboundJobEnqueueTests.swift
//  PostQuantumSolaceTests
//
//  Red/green proofs that public outbound compose either creates durable per-device
//  PQS jobs or throws a typed failure. Silent success with zero jobs is forbidden.
//

import Crypto
import Foundation
import NeedleTailLogger
import SessionModels
import Testing
@testable import PQSSession

extension EndToEndTests {

    private func jobsMatchingSharedId(
        _ jobs: [JobModel],
        sharedId: String,
        symmetricKey: SymmetricKey
    ) async -> [JobModel] {
        var matched = [JobModel]()
        for job in jobs {
            guard let props = await job.props(symmetricKey: symmetricKey),
                  case .writeMessage(let outbound) = props.task.task,
                  outbound.sharedId == sharedId else { continue }
            matched.append(job)
        }
        return matched
    }

    @Test("Missing offer identity throws instead of silent success with zero jobs")
    func missingOfferIdentityThrowsAndCreatesNeitherMessageNorJobs() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceStore = createSenderStore()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        var sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        let aliceStream = AsyncStream<ReceivedMessage> { bobTransport.continuation = $0 }
        let bobStream = AsyncStream<ReceivedMessage> { aliceTransport.continuation = $0 }

        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: sd)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }
        bobTask = Task {
            for await received in bobStream {
                _ = try? await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }

        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        // Warm a lane so chat fan-out has bob identities, then force a missing offer target.
        try await _senderSession.send(
            recipient: .nickname("bob"),
            text: "warmup-before-missing-offer",
            sharedIdOverride: "enqueue-warmup-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(200))

        let missingDeviceId = UUID().uuidString
        sd.forcedRetrieveUserInfo = ("bob", missingDeviceId)
        await _senderSession.setPQSSessionDelegate(conformer: sd)

        let sharedId = "missing-offer-\(UUID().uuidString)"
        var thrown: Error?
        do {
            try await _senderSession.send(
                recipient: .nickname("bob"),
                text: "should not silently succeed",
                sharedIdOverride: sharedId)
        } catch {
            thrown = error
        }

        #expect(
            thrown as? PQSError == .missingSessionIdentity,
            "Missing offer identity must throw missingSessionIdentity so ChatBar restores the draft")

        let cache = try #require(await _senderSession.cache)
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        #expect(try await cache.fetchCachedMessages(sharedId: sharedId).isEmpty)
        let cacheJobs = await jobsMatchingSharedId(
            try await cache.fetchJobs(),
            sharedId: sharedId,
            symmetricKey: symmetricKey)
        #expect(cacheJobs.isEmpty)
        let storeJobs = await jobsMatchingSharedId(
            aliceStore.persistedJobs,
            sharedId: sharedId,
            symmetricKey: symmetricKey)
        #expect(storeJobs.isEmpty)
    }

    @Test("Persistable one-device DM creates one local message and at least one durable job")
    func persistableOneDeviceDMCreatesLocalMessageAndDurableJob() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceStore = createSenderStore()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        let aliceStream = AsyncStream<ReceivedMessage> { bobTransport.continuation = $0 }
        let bobStream = AsyncStream<ReceivedMessage> { aliceTransport.continuation = $0 }

        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: sd)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }
        bobTask = Task {
            for await received in bobStream {
                _ = try? await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }

        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        let sharedId = "durable-dm-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname("bob"),
            text: "durable enqueue proof",
            sharedIdOverride: sharedId)

        let cache = try #require(await _senderSession.cache)
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        let messages = try await cache.fetchCachedMessages(sharedId: sharedId)
        #expect(messages.count == 1)

        // Successful transport deletes the job after send; assert the createJob history
        // so we prove the disk boundary was crossed even if the live queue is empty.
        let createdJobs = await jobsMatchingSharedId(
            aliceStore.createJobHistory,
            sharedId: sharedId,
            symmetricKey: symmetricKey)
        #expect(
            createdJobs.count >= 1,
            "Disk-boundary createJob must persist at least one job for the peer device")
    }

    @Test("createJob persistence failure surfaces to send and fails local row")
    func createJobFailureThrowsAndDoesNotClaimSuccess() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceStore = createSenderStore()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        let aliceStream = AsyncStream<ReceivedMessage> { bobTransport.continuation = $0 }
        let bobStream = AsyncStream<ReceivedMessage> { aliceTransport.continuation = $0 }

        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: sd)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }
        bobTask = Task {
            for await received in bobStream {
                _ = try? await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }

        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        // Warm lanes with a successful send first.
        try await _senderSession.send(
            recipient: .nickname("bob"),
            text: "warmup-before-createJob-failure",
            sharedIdOverride: "enqueue-jobfail-warmup-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(200))

        await aliceStore.setCreateJobError(PQSError.databaseNotInitialized)

        let sharedId = "createjob-fail-\(UUID().uuidString)"
        var thrown: Error?
        do {
            try await _senderSession.send(
                recipient: .nickname("bob"),
                text: "must surface store failure",
                sharedIdOverride: sharedId)
        } catch {
            thrown = error
        }

        #expect(thrown != nil, "createJob failure must not return success")
        #expect(
            thrown as? PQSError == .outboundEnqueueIncomplete
                || thrown as? PQSError == .databaseNotInitialized,
            "Expected enqueue incomplete or the underlying store error, got \(String(describing: thrown))")

        let cache = try #require(await _senderSession.cache)
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        let messages = try await cache.fetchCachedMessages(sharedId: sharedId)
        if let message = messages.first,
           let props = await message.props(symmetricKey: symmetricKey) {
            #expect(
                props.deliveryState != .sending,
                "Local row must not remain .sending after enqueue failure")
        }

        let storeJobs = await jobsMatchingSharedId(
            aliceStore.persistedJobs,
            sharedId: sharedId,
            symmetricKey: symmetricKey)
        #expect(storeJobs.isEmpty)
    }

    @Test("Nonviable compose still persists durable jobs with zero transport sends")
    func nonviableComposePersistsJobsWithoutTransport() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceStore = createSenderStore()
        let bobStore = createRecipientStore()
        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        let aliceStream = AsyncStream<ReceivedMessage> { bobTransport.continuation = $0 }
        let bobStream = AsyncStream<ReceivedMessage> { aliceTransport.continuation = $0 }

        try await createSenderSession(
            store: aliceStore,
            transport: aliceTransport,
            sessionDelegate: sd)
        try await createRecipientSession(
            store: bobStore,
            transport: bobTransport,
            sessionDelegate: rsd)

        aliceTask = Task {
            for await received in aliceStream {
                _ = try? await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }
        bobTask = Task {
            for await received in bobStream {
                _ = try? await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
            }
        }

        try await createFriendship(
            aliceSession: _senderSession,
            sd: sd,
            bobSession: _recipientSession,
            rsd: rsd)

        try await _senderSession.send(
            recipient: .nickname("bob"),
            text: "warmup-before-nonviable",
            sharedIdOverride: "enqueue-nonviable-warmup-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(200))

        let sendsBefore = await aliceTransport.sendMessageCallCount
        await _senderSession.setConnectivity(false)

        let sharedId = "nonviable-enqueue-\(UUID().uuidString)"
        try await _senderSession.send(
            recipient: .nickname("bob"),
            text: "queued while nonviable",
            sharedIdOverride: sharedId)

        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        let storeJobs = await jobsMatchingSharedId(
            aliceStore.persistedJobs,
            sharedId: sharedId,
            symmetricKey: symmetricKey)
        #expect(storeJobs.count >= 1)
        #expect(await aliceTransport.sendMessageCallCount == sendsBefore)
    }
}

extension MockIdentityStore {
    func setCreateJobError(_ error: Error?) {
        createJobError = error
    }
}
