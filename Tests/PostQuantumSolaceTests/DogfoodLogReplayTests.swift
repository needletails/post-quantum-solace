//
//  DogfoodLogReplayTests.swift
//  PostQuantumSolaceTests
//
//  Behavioral replays of 2026-07-24 multi-device dogfood logs:
//  - CHILD_DEVICE_2: send hung / failed on find-configuration -1001
//  - CHILD_DEVICE: linked personal maxSkipped → bodyDecryptionFailed → orphan/remint
//
//  These tests assert the *desired* dogfood UX. Failures prove the bug still exists.
//

import DoubleRatchetKit
import Foundation
import NeedleTailLogger
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {

    // MARK: - N1: warm send must not block on hanging findConfiguration

    /// CHILD_DEVICE_2: after traffic has already warmed peer lanes, a staging API hang on
    /// `find-configuration` must not strand `writeTextMessage` for minutes.
    ///
    /// Desired: warm chat fan-out uses `lastVerifiedDeviceIdsBySecretName` and completes
    /// without awaiting a hung `findConfiguration`.
    @Test("dogfood N1: warm chat send completes while findConfiguration hangs")
    func dogfoodN1_warmChatSendCompletesWhileFindConfigurationHangs() async throws {
        var aliceTask: Task<Void, Never>?
        var bobTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                bobTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let bobTransport = _MockTransportDelegate(session: _recipientSession, store: store)
        let sd = SessionDelegate(session: _senderSession)
        let rsd = SessionDelegate(session: _recipientSession)

        let aliceStream = AsyncStream<ReceivedMessage> { bobTransport.continuation = $0 }
        let bobStream = AsyncStream<ReceivedMessage> { aliceTransport.continuation = $0 }

        try await createSenderSession(
            store: createSenderStore(),
            transport: aliceTransport,
            sessionDelegate: sd)
        try await createRecipientSession(
            store: createRecipientStore(),
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

        // Warm peer lanes + verified-device cache (friendship + one delivered text).
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "warm-baseline",
            sharedIdOverride: "dogfood-n1-warm-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(300))

        let verifiedCache = await _senderSession.lastVerifiedDeviceIdsBySecretName["bob"]
        #expect(
            verifiedCache?.isEmpty == false,
            "Precondition: warm path requires lastVerifiedDeviceIdsBySecretName for bob")

        await aliceTransport.resetCallTracking()
        // Long cancellable hang — dogfood -1001 shape without a never-resume
        // continuation that would strand the suite after the 2s deadline cancels.
        aliceTransport.findConfigurationHang = {
            try? await Task.sleep(for: .seconds(60))
        }
        aliceTransport.findConfigurationFaultSecretNames = ["bob", "alice"]

        let warmSharedId = "dogfood-n1-warm-send-\(UUID().uuidString)"
        let sendTask = Task {
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "must-not-hang-on-find-configuration",
                sharedIdOverride: warmSharedId)
        }

        let completed: Bool
        do {
            completed = try await withThrowingTaskGroup(of: Bool.self) { group in
                group.addTask {
                    _ = try await sendTask.value
                    return true
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(5))
                    return false
                }
                let first = try await group.next() ?? false
                group.cancelAll()
                sendTask.cancel()
                return first
            }
        } catch {
            sendTask.cancel()
            Issue.record("Warm send threw while findConfiguration hung: \(error)")
            return
        }

        let findConfigurationCallCount = await aliceTransport.findConfigurationCallCount
        #expect(
            completed,
            """
            BUG (CHILD_DEVICE_2): warm writeTextMessage blocked on hanging findConfiguration. \
            Expected encrypt path to avoid awaiting live config when verified device cache \
            already matches. findConfigurationCallCount=\(findConfigurationCallCount)
            """)
        if completed {
            #expect(
                findConfigurationCallCount == 0,
                "Warm send must not call findConfiguration when verified cache matches")
        }
    }

    @Test("persist-first: established DM row exists before remote configuration lookup")
    func establishedDMPersistsBeforeRemoteConfigurationLookup() async throws {
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
            store: createRecipientStore(),
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

        let localBobLanes = try await _senderSession.getSessionIdentities(with: "bob")
        #expect(!localBobLanes.isEmpty, "Precondition: established bob lanes")
        await _senderSession.test_removeLastVerifiedDeviceIds(for: "bob")

        let sharedId = "persist-before-config-\(UUID().uuidString)"
        let observation = CallTracker()
        aliceTransport.beforeFindConfiguration = { secretName in
            guard secretName == "bob" else { return }
            let persisted = await aliceStore.createdMessages.contains {
                $0.sharedId == sharedId
            }
            await observation.record(
                secretName: secretName,
                deviceId: "",
                keyCount: persisted ? 1 : 0)
        }

        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "persist before config",
            sharedIdOverride: sharedId)

        let calls = await observation.calls
        #expect(!calls.isEmpty, "Cold verified memo should exercise remote configuration")
        #expect(
            calls.allSatisfy { $0.keyCount == 1 },
            "The local message row must exist before findConfiguration starts")
    }

    // MARK: - N1b: cold findConfiguration timeout fails fast when no local lanes

    /// When there are no local recipient lanes and live `findConfiguration` times out,
    /// the send must fail quickly (not strand for the URLSession 300s default).
    /// When local lanes exist, offline-first (N3) persists instead — that is covered
    /// by dogfood N3.
    @Test("dogfood N1b: findConfiguration timedOut fails send within one second")
    func dogfoodN1b_findConfigurationTimedOutFailsSendWithinOneSecond() async throws {
        var aliceTask: Task<Void, Never>?
        defer {
            Task {
                aliceTask?.cancel()
                await shutdownSessions()
            }
        }

        let aliceTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let sd = SessionDelegate(session: _senderSession)

        try await createSenderSession(
            store: createSenderStore(),
            transport: aliceTransport,
            sessionDelegate: sd)

        // No friendship / no bob lanes: live find is required and will time out.
        await _senderSession.test_removeLastVerifiedDeviceIds(for: "bob")
        aliceTransport.findConfigurationError = URLError(.timedOut)
        aliceTransport.findConfigurationFaultSecretNames = ["bob"]

        enum Deadline: Error { case exceeded }

        let started = ContinuousClock.now
        var sendError: Error?
        var hitDeadline = false
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await self._senderSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "cold-find-should-fail-fast",
                        sharedIdOverride: "dogfood-n1b-\(UUID().uuidString)")
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(1))
                    throw Deadline.exceeded
                }
                do {
                    try await group.next()
                    group.cancelAll()
                } catch {
                    group.cancelAll()
                    throw error
                }
            }
            Issue.record("Expected cold findConfiguration timedOut to fail the send")
        } catch is Deadline {
            hitDeadline = true
        } catch {
            sendError = error
        }

        let elapsed = ContinuousClock.now - started
        #expect(
            !hitDeadline && elapsed < .seconds(1.2),
            "BUG: findConfiguration timedOut path did not fail-fast (elapsed=\(elapsed)); dogfood waited minutes on -1001")
        #expect(
            sendError != nil,
            "Cold send with no local lanes must surface an error when findConfiguration throws URLError.timedOut")
    }

    // MARK: - N3: offline compose must cache locally and drain on reconnect

    /// Intended UX: compose while offline / API flaky → message stored locally as
    /// sending + job queued → when viable again, `resumeJobQueue` delivers.
    ///
    /// Today identity resolution hard-awaits `findConfiguration` before
    /// `createEncryptableTask`, so CHILD_DEVICE_2's `-1001` /
    /// `cannotFindUserConfiguration` aborts with **nothing cached** and no
    /// automatic retry after reconnect.
    @Test("dogfood N3: offline compose with warm lanes caches and drains on resume")
    func dogfoodN3_offlineComposeWithWarmLanesCachesAndDrainsOnResume() async throws {
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
            text: "warm-before-offline",
            sharedIdOverride: "dogfood-n3-warm-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(300))

        #expect(
            await _senderSession.lastVerifiedDeviceIdsBySecretName["bob"]?.isEmpty == false,
            "Precondition: warm verified-device cache for bob")
        // Local peer SessionIdentity rows must still exist after we drop the
        // verified-id memo — dogfood often has lanes but a flaky live config lookup.
        let localBobLanes = try await _senderSession.getSessionIdentities(with: "bob")
        #expect(!localBobLanes.isEmpty, "Precondition: local bob SessionIdentity lanes exist")

        // Dogfood shape: API/config lookup fails while IRC/local crypto state remains.
        // Clearing the verified-id memo forces chat fan-out onto live findConfiguration
        // (CHILD_DEVICE_2 -1001 / cannotFindUserConfiguration path).
        await _senderSession.test_removeLastVerifiedDeviceIds(for: "bob")
        await _senderSession.setViability(false)
        aliceTransport.findConfigurationError = URLError(.timedOut)
        aliceTransport.findConfigurationFaultSecretNames = ["bob", "alice"]

        let offlineSharedId = "dogfood-n3-offline-\(UUID().uuidString)"
        var composeError: Error?
        do {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "composed while offline / API timed out",
                sharedIdOverride: offlineSharedId)
        } catch {
            composeError = error
        }

        let cache = try #require(await _senderSession.cache)
        let cachedMessages = try await cache.fetchCachedMessages(sharedId: offlineSharedId)
        let jobs = try await cache.fetchJobs()
        let localCreated = await aliceStore.createdMessages.contains { $0.sharedId == offlineSharedId }

        #expect(
            composeError == nil,
            """
            BUG: offline compose threw \(String(describing: composeError)) instead of caching. \
            Dogfood CHILD_DEVICE_2 lost sends on find-configuration -1001 / \
            cannotFindUserConfiguration with nothing left to drain on reconnect.
            """)
        let hasLocalRow = !cachedMessages.isEmpty || localCreated
        let hasQueuedJob = !jobs.isEmpty
        #expect(
            hasLocalRow,
            "BUG: offline compose left no local message for sharedId \(offlineSharedId)")
        #expect(
            hasQueuedJob || hasLocalRow,
            "BUG: offline compose left no outbound job to drain on resume (jobs=\(jobs.count))")

        // Come back online: clear API fault, restore viability, drain.
        aliceTransport.findConfigurationError = nil
        aliceTransport.findConfigurationHang = nil
        aliceTransport.findConfigurationFaultSecretNames = nil
        await _senderSession.setViability(true)
        try await _senderSession.resumeJobQueue()

        func waitUntil(
            timeoutSeconds: TimeInterval = 8,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        let delivered = await waitUntil {
            await bobStore.createdMessages.contains { $0.sharedId == offlineSharedId }
        }
        #expect(
            delivered,
            """
            BUG: cached offline message \(offlineSharedId) did not deliver after \
            viability restore + resumeJobQueue
            """)
    }

    // MARK: - C1: linked personal maxSkipped → settle or purge sharedId

    /// CHILD_DEVICE: personal backlog hits maxSkipped then bodyDecryptionFailed.
    /// Desired: the failed sharedId either decrypts via orphan-resend OR is durably
    /// settled/purged (no immortal redelivery), and a subsequent personal sync lands.
    @Test("dogfood C1: linked personal maxSkipped either heals or purges failed sharedId")
    func dogfoodC1_linkedPersonalMaxSkippedHealsOrPurgesSharedId() async throws {
        actor FlowProbe {
            var failedSharedId: String?
            var maxSkippedCount = 0
            var inboundAttemptsForFailed = 0
            var decryptedFailed = false

            func markFailed(_ id: String) {
                if failedSharedId == nil {
                    failedSharedId = id
                }
                maxSkippedCount += 1
            }

            func noteInbound(messageId: String) {
                if messageId == failedSharedId {
                    inboundAttemptsForFailed += 1
                }
            }

            func markDecrypted(_ id: String) {
                if id == failedSharedId {
                    decryptedFailed = true
                }
            }
        }

        actor DropGate {
            let dropCount: Int
            var armed = false
            var dropped = 0

            init(dropCount: Int) { self.dropCount = dropCount }
            func arm() { armed = true }
            func shouldDropNext() -> Bool {
                guard armed else { return false }
                if dropped < dropCount {
                    dropped += 1
                    return true
                }
                return false
            }

            func isFailingDeliveryCandidate() -> Bool {
                armed && dropped >= dropCount
            }
        }

        func waitUntil(
            timeoutSeconds: TimeInterval = 10,
            _ condition: @escaping @Sendable () async -> Bool
        ) async -> Bool {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while Date() < deadline {
                if await condition() { return true }
                try? await Task.sleep(for: .milliseconds(50))
            }
            return false
        }

        var transportTasks = [Task<Void, Never>]()
        defer {
            for task in transportTasks { task.cancel() }
            Task { await shutdownSessions() }
        }

        let senderStore = createSenderStore()
        let senderChildStore = createSenderChildStore1()
        let recipientStore = createRecipientStore()

        let senderParentTransport = _MockTransportDelegate(session: _senderSession, store: store)
        let senderChildTransport = _MockTransportDelegate(session: _senderChildSession1, store: store)
        let recipientParentTransport = _MockTransportDelegate(session: _recipientSession, store: store)

        let probe = FlowProbe()
        let gate = DropGate(dropCount: 12)

        let senderDelegate = SessionDelegate(session: _senderSession)
        let recipientDelegate = SessionDelegate(session: _recipientSession)
        try await createSenderSession(
            store: senderStore,
            transport: senderParentTransport,
            sessionDelegate: senderDelegate)
        try await createRecipientSession(
            store: recipientStore,
            transport: recipientParentTransport,
            sessionDelegate: recipientDelegate)
        try await linkSenderChildSession1(
            store: senderChildStore,
            transport: senderChildTransport,
            useProvidedTransport: true)

        guard let senderLinkedConfiguration =
                await _senderChildSession1.sessionContext?.activeUserConfiguration
        else {
            Issue.record("Linked sender configuration should be available")
            return
        }
        if let senderIndex = await store.userConfigurations.firstIndex(where: {
            $0.secretName == sMockUserData.ssn
        }) {
            await store.setUserConfigurations(index: senderIndex, config: senderLinkedConfiguration)
        }
        try await _senderSession.updateUserConfiguration(
            senderLinkedConfiguration.getVerifiedDevices())

        guard let senderParentId = await _senderSession.sessionContext?.sessionUser.deviceId,
              let senderChildId = await _senderChildSession1.sessionContext?.sessionUser.deviceId,
              let recipientParentId = await _recipientSession.sessionContext?.sessionUser.deviceId
        else {
            Issue.record("Device sessions should be initialized")
            return
        }

        // Drop only personal/sibling sync frames to the linked child (CHILD_DEVICE shape).
        senderParentTransport.shouldDeliver = { received in
            guard received.recipientDeviceId == senderChildId else { return true }
            guard received.transportEvent == nil else { return true }
            let shouldDrop = await gate.shouldDropNext()
            return !shouldDrop
        }

        let routes: [UUID: PQSSession] = [
            senderParentId: _senderSession,
            senderChildId: _senderChildSession1,
            recipientParentId: _recipientSession
        ]

        let route: @Sendable (ReceivedMessage) async -> Void = { received in
            guard let recipientDeviceId = received.recipientDeviceId,
                  let target = routes[recipientDeviceId]
            else { return }

            if recipientDeviceId == senderChildId,
               received.transportEvent == nil,
               await gate.isFailingDeliveryCandidate(),
               await probe.failedSharedId == nil {
                await probe.markFailed(received.messageId)
            }
            if recipientDeviceId == senderChildId {
                await probe.noteInbound(messageId: received.messageId)
            }

            do {
                _ = try await target.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId,
                    logicalMessageId: received.logicalMessageId)
                if recipientDeviceId == senderChildId {
                    await probe.markDecrypted(received.messageId)
                }
            } catch let ratchetError as RatchetError where ratchetError == .maxSkippedHeadersExceeded {
                if recipientDeviceId == senderChildId {
                    await probe.markFailed(received.messageId)
                }
            } catch {
                // bodyDecryptionFailed / other recoverable — keep receiving
            }
        }

        let parentStream = AsyncStream<ReceivedMessage> { senderParentTransport.continuation = $0 }
        let childStream = AsyncStream<ReceivedMessage> { senderChildTransport.continuation = $0 }
        let recipientStream = AsyncStream<ReceivedMessage> { recipientParentTransport.continuation = $0 }

        transportTasks = [
            Task { for await received in parentStream { await route(received) } },
            Task { for await received in childStream { await route(received) } },
            Task { for await received in recipientStream { await route(received) } }
        ]

        try await createFriendship(
            aliceSession: _senderSession,
            sd: senderDelegate,
            bobSession: _recipientSession,
            rsd: recipientDelegate)

        #expect(
            await waitUntil {
                (try? await self._senderSession.hasInitializedOutboundRatchetForPeer("bob")) == true
            },
            "Friendship ratchet must be ready before personal gap-drop")

        // Baseline personal sync before arming drops.
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "personal-baseline-before-gap",
            sharedIdOverride: "dogfood-c1-baseline-\(UUID().uuidString)")
        try? await Task.sleep(for: .milliseconds(300))

        await gate.arm()

        for i in 0..<13 {
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "personal-gap-\(i)",
                sharedIdOverride: "dogfood-c1-gap-\(i)-\(UUID().uuidString)")
        }

        let sawMaxSkipped = await waitUntil { await probe.failedSharedId != nil }
        #expect(
            sawMaxSkipped,
            "Expected linked child personal lane to identify a failing sharedId after gap (CHILD_DEVICE maxSkipped)")

        guard let failed = await probe.failedSharedId else { return }

        // Heal window: orphan-resend / recovery should decrypt the sharedId into the
        // child store (strongest success). Falling short is the CHILD_DEVICE bug.
        let healed = await waitUntil(timeoutSeconds: 12) {
            if await senderChildStore.createdMessages.contains(where: { $0.sharedId == failed }) {
                return true
            }
            return await probe.decryptedFailed
        }

        // New traffic after the failure window must still sync to the linked child.
        let freshSharedId = "dogfood-c1-fresh-\(UUID().uuidString)"
        try await _senderSession.writeTextMessage(
            recipient: .nickname("bob"),
            text: "personal-after-heal",
            sharedIdOverride: freshSharedId)

        let freshLanded = await waitUntil(timeoutSeconds: 10) {
            await senderChildStore.createdMessages.contains(where: { $0.sharedId == freshSharedId })
        }

        let inboundAttempts = await probe.inboundAttemptsForFailed
        let maxSkippedCount = await probe.maxSkippedCount
        #expect(
            healed || freshLanded,
            """
            BUG (CHILD_DEVICE): failed personal sharedId \(failed) did not decrypt after \
            orphan-resend, and fresh personal sync \(freshSharedId) also failed to land. \
            inboundAttempts=\(inboundAttempts) maxSkippedCount=\(maxSkippedCount)
            """)
        #expect(
            inboundAttempts < 20,
            "BUG: failed sharedId \(failed) was redelivered unboundedly (inboundAttempts=\(inboundAttempts))")
        #expect(
            freshLanded,
            "BUG: linked child did not receive new personal sync \(freshSharedId) after maxSkipped window")
    }
}

extension PQSSession {
    /// Test-only: mutate verified-device cache without touching production APIs.
    func test_removeLastVerifiedDeviceIds(for secretName: String) {
        lastVerifiedDeviceIdsBySecretName.removeValue(forKey: secretName)
    }
}

// MARK: - C2b–C2f: recovery storm (CHILD_DEVICE_2 archive/remint death spiral)

@Suite("Dogfood C2 recovery storm policy")
struct DogfoodRecoveryStormPolicyTests {
    @Test("dogfood C2b: same sharedId defers archived fallback at most once until heal")
    func dogfoodC2b_sameSharedIdDefersArchiveFallbackAtMostOnce() {
        let sharedId = "1FA1D17E-A326-43D8-8605-49AECD3543ED"
        let token = ArchivedInboundFallbackToken(
            senderSecretName: "alice",
            senderDeviceId: UUID(),
            envelopeMessageId: sharedId,
            fingerprint: Data("offline-poison-ct".utf8))
        var exhausted = Set<String>()
        var pending = Set<String>()
        var deferCount = 0

        for _ in 0..<20 {
            guard InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: token,
                exhausted: exhausted,
                pendingPass: pending
            ) else { continue }
            deferCount += 1
            pending.insert(token.storageKey)
            // Production removes pending at archive-pass start, then marks exhausted.
            pending.remove(token.storageKey)
            exhausted = InboundRecoveryStormPolicy.exhaustedAfterArchivePassCompleted(
                current: exhausted,
                token: token
            )
        }

        #expect(
            deferCount == 1,
            "BUG: same poison sharedId re-deferred \(deferCount)× (dogfood CHILD_DEVICE_2: 2589)")
    }

    @Test("dogfood C2c: after archive exhaustion, redelivery does not re-defer")
    func dogfoodC2c_noArchiveDeferAfterExhaustion() {
        let token = ArchivedInboundFallbackToken(
            senderSecretName: "alice",
            senderDeviceId: UUID(),
            envelopeMessageId: "saturate-then-replay",
            fingerprint: Data("poison".utf8))
        let exhausted: Set = [token.storageKey]
        #expect(
            !InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: token,
                exhausted: exhausted,
                pendingPass: []
            ))
    }

    @Test("dogfood C2f: clearing exhaustion re-arms one archive defer")
    func dogfoodC2f_newArchiveAfterExhaustReArmsDefer() {
        let token = ArchivedInboundFallbackToken(
            senderSecretName: "alice",
            senderDeviceId: UUID(),
            envelopeMessageId: "rearm-after-new-archive",
            fingerprint: Data("poison".utf8))
        var exhausted: Set = [token.storageKey]
        #expect(
            !InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: token,
                exhausted: exhausted,
                pendingPass: []))
        // Heal / new archive generation clears exhaustion for that ciphertext.
        exhausted.remove(token.storageKey)
        #expect(
            InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: token,
                exhausted: exhausted,
                pendingPass: []))
    }

    @Test("dogfood C2g: new fingerprint clears exhaustion and re-arms one archive defer")
    func dogfoodC2g_newFingerprintReArmsArchiveDefer() {
        let sharedId = "9ABB24B1-AB85-4927-887D-97794A6C5830"
        let deviceId = UUID()
        let prior = ArchivedInboundFallbackToken(
            senderSecretName: "alice",
            senderDeviceId: deviceId,
            envelopeMessageId: sharedId,
            fingerprint: Data("offline-poison-ct".utf8))
        let remint = ArchivedInboundFallbackToken(
            senderSecretName: "alice",
            senderDeviceId: deviceId,
            envelopeMessageId: sharedId,
            fingerprint: Data("orphan-remint-ct".utf8))
        let exhausted: Set = [prior.storageKey]

        #expect(
            !InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: prior,
                exhausted: exhausted,
                pendingPass: []))
        #expect(
            InboundRecoveryStormPolicy.shouldDeferArchivedFallback(
                token: remint,
                exhausted: exhausted,
                pendingPass: []),
            "BUG: reminted CT token must retain an independent archive pass")
        #expect(InboundRecoveryStormPolicy.tokensAreIndependent(prior, remint))
    }
}

// MARK: - C3: same sharedId must not remint on every rearmNack (CHILD_DEVICE 2FA48892)

@Suite("Dogfood C3 orphan remint thrash policy")
struct DogfoodOrphanRemintThrashPolicyTests {
    @Test("dogfood C3a: settled recovery NACK escape-remints once; spent budget retransports")
    func dogfoodC3a_sameSharedIdRemintsAtMostOnceAcrossRearms() {
        let recoverySession = UUID()
        var messageRecordSessionId: UUID? = nil
        var recoverySessionId: UUID? = nil
        var initiatingMark: UUID? = nil
        var markIsStateLess = false
        var mintCount = 0

        // Wave 1 / first NACK: no MessageRecord recovery match → mint.
        let first = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: messageRecordSessionId,
            recoverySessionId: recoverySessionId,
            initiatingMarkSessionId: initiatingMark,
            markIsStateLess: markIsStateLess)
        #expect(first == .mintFresh)
        mintCount += 1
        recoverySessionId = recoverySession
        initiatingMark = recoverySession
        markIsStateLess = true

        // Still state-less before encrypt → reuse mark (no second mint).
        let reuse = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: messageRecordSessionId,
            recoverySessionId: recoverySessionId,
            initiatingMarkSessionId: initiatingMark,
            markIsStateLess: markIsStateLess)
        #expect(reuse == .reuseStateLessMark)

        // Encrypt advances ratchet + updates MessageRecord to recovery SessionID.
        markIsStateLess = false
        messageRecordSessionId = recoverySession

        // Wave 2 / first rearmNack on settled recovery: escape remint once (new OTK).
        // Identical-CT retransport cannot rearm; budget still caps mint thrash (C3).
        let firstRearm = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: messageRecordSessionId,
            recoverySessionId: recoverySessionId,
            initiatingMarkSessionId: initiatingMark,
            markIsStateLess: markIsStateLess,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: 0)
        #expect(
            firstRearm == .mintFreshAfterRetransportProveFailed,
            "BUG: settled recovery NACK must escape-remint, got \(firstRearm)")
        mintCount += 1
        #expect(mintCount == 2)

        // Spent budget: next settled NACK retransports reminted CT (not another remint).
        let postEscape = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: messageRecordSessionId,
            recoverySessionId: recoverySessionId,
            initiatingMarkSessionId: initiatingMark,
            markIsStateLess: markIsStateLess,
            priorRetransportCount: 0,
            remintsAfterRetransportProveFail: 1)
        #expect(postEscape == .retransportAlreadyServiced)
        #expect(mintCount == 2)
    }

    @Test("dogfood C3b: MessageRecord matching recovery escape-remints once when budget remains")
    func dogfoodC3b_messageRecordRecoveryBeatsAdvancedSticky() {
        let sessionId = UUID()
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: sessionId,
            recoverySessionId: sessionId,
            initiatingMarkSessionId: sessionId,
            markIsStateLess: false)
        #expect(
            decision == .mintFreshAfterRetransportProveFailed,
            "BUG: settled recovery with budget must escape-remint, got \(decision)")
    }

    @Test("dogfood C3c: live recovery reuses wave for unrelated MessageRecord")
    func dogfoodC3c_liveRecoveryReusesWaveForUnrelatedMessageRecord() {
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: UUID(),
            recoverySessionId: UUID(),
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            recoverySessionIsLiveActive: true)
        #expect(
            decision == .reuseRecoveryWave,
            "BUG: live recovery reminted instead of wave reuse, got \(decision)")
    }

    @Test("dogfood C3c: dead recovery still allows mint for unrelated MessageRecord")
    func dogfoodC3c_deadRecoveryStillMints() {
        let decision = OrphanResendRemintPolicy.decision(
            messageRecordSessionId: UUID(),
            recoverySessionId: UUID(),
            initiatingMarkSessionId: nil,
            markIsStateLess: false,
            recoverySessionIsLiveActive: false)
        #expect(decision == .mintFresh)
    }
}

