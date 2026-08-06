//
//  OutboundCoalescingTests.swift
//  PostQuantumSolaceTests
//
//  Red/green proofs for ephemeral outbound job coalescing.
//
//  Ephemeral state publishes (e.g. host consent blobs, schedule syncs) are
//  regenerated on every registration. Without a supersede boundary, every
//  short-lived session leaves its unsent copies in the durable job queue and
//  the next launch drains all of them into offline recipients' spools
//  (observed in production: 22 launches -> 132 stale packets flooding five
//  device lanes). A keyed enqueue must replace the pending job for the same
//  lane instead of accumulating behind it.
//
//  Contract:
//  - `writeTextMessage(coalescingKey:)` threads an opaque host key onto the
//    per-device outbound job.
//  - `feedTask` deletes pending (not in-flight) jobs with the same key and
//    the same recipient identity lane before persisting the new job.
//  - Coalescing applies only to non-persisted outbound jobs. Persisted user
//    messages are never superseded.
//

import Crypto
import Foundation
import NeedleTailLogger
import SessionModels
import Testing
@testable import PQSSession

extension EndToEndTests {

    private func ephemeralJobs(
        _ jobs: [JobModel],
        coalescingKey: String?,
        symmetricKey: SymmetricKey
    ) async -> [(job: JobModel, sharedId: String)] {
        var matched = [(JobModel, String)]()
        for job in jobs {
            guard let props = await job.props(symmetricKey: symmetricKey),
                  case .writeMessage(let outbound) = props.task.task,
                  outbound.isPersistedOutbound == false,
                  outbound.coalescingKey == coalescingKey else { continue }
            matched.append((job, outbound.sharedId))
        }
        return matched
    }

    @Test("Keyed ephemeral send supersedes the pending job for the same lane")
    func keyedEphemeralSendSupersedesPendingJobForSameLane() async throws {
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

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "warmup-before-coalesce",
            sharedIdOverride: "coalesce-warmup-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(200))

        // Persist without transporting so pending jobs are observable.
        await _senderSession.setViability(false)

        let key = "test.consent:bob"
        let staleSharedId = "coalesce-stale-\(UUID().uuidString)"
        let freshSharedId = "coalesce-fresh-\(UUID().uuidString)"

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "stale consent blob",
            sharedIdOverride: staleSharedId,
            shouldPersistOverride: false,
            coalescingKey: key)
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "fresh consent blob",
            sharedIdOverride: freshSharedId,
            shouldPersistOverride: false,
            coalescingKey: key)

        let cache = try #require(await _senderSession.cache)
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        let pending = await ephemeralJobs(
            try await cache.fetchJobs(),
            coalescingKey: key,
            symmetricKey: symmetricKey)

        #expect(
            pending.count == 1,
            "Same key + same lane must keep exactly one pending job, found \(pending.count)")
        #expect(
            pending.first?.sharedId == freshSharedId,
            "The surviving job must be the newest publish")
    }

    @Test("Nil-key ephemeral sends still accumulate (no implicit coalescing)")
    func nilKeyEphemeralSendsAccumulate() async throws {
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

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "warmup-before-nilkey",
            sharedIdOverride: "nilkey-warmup-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(200))

        await _senderSession.setViability(false)

        let firstSharedId = "nilkey-first-\(UUID().uuidString)"
        let secondSharedId = "nilkey-second-\(UUID().uuidString)"
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "first control frame",
            sharedIdOverride: firstSharedId,
            shouldPersistOverride: false)
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "second control frame",
            sharedIdOverride: secondSharedId,
            shouldPersistOverride: false)

        let cache = try #require(await _senderSession.cache)
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        let pending = await ephemeralJobs(
            try await cache.fetchJobs(),
            coalescingKey: nil,
            symmetricKey: symmetricKey)
        let pendingSharedIds = Set(pending.map(\.sharedId))

        #expect(
            pendingSharedIds.isSuperset(of: [firstSharedId, secondSharedId]),
            "Nil-key ephemeral jobs must never coalesce implicitly")
    }

    @Test("Keyed supersede never deletes persisted user-message jobs")
    func keyedSupersedeNeverTouchesPersistedJobs() async throws {
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

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "warmup-before-persisted-guard",
            sharedIdOverride: "guard-warmup-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(200))

        await _senderSession.setViability(false)

        // Queue a persisted user message while offline.
        let userSharedId = "guard-user-\(UUID().uuidString)"
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "real user message queued offline",
            sharedIdOverride: userSharedId)

        // A keyed ephemeral publish to the same lane must not disturb it.
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "consent blob",
            sharedIdOverride: "guard-consent-\(UUID().uuidString)",
            shouldPersistOverride: false,
            coalescingKey: "test.consent:bob")

        let cache = try #require(await _senderSession.cache)
        let symmetricKey = try await _senderSession.getDatabaseSymmetricKey()
        var persistedUserJobCount = 0
        for job in try await cache.fetchJobs() {
            guard let props = await job.props(symmetricKey: symmetricKey),
                  case .writeMessage(let outbound) = props.task.task,
                  outbound.sharedId == userSharedId,
                  outbound.isPersistedOutbound else { continue }
            persistedUserJobCount += 1
        }
        #expect(
            persistedUserJobCount >= 1,
            "Persisted user-message jobs must survive keyed ephemeral publishes")
    }
}
