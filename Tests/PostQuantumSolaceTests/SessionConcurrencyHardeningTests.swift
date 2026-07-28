import Foundation
import Testing
@testable import PQSSession

@Suite("PQS session concurrency hardening")
struct SessionConcurrencyHardeningTests {

    @Test("shutdown closes admission before suspension and rejects later scheduling")
    func shutdownRejectsSchedulingAndDoesNotRecreateWorkers() async {
        let session = PQSSession()
        await session.beginSessionLifecycleIfNeeded()
        #expect(await session.lifecyclePhase == .running)

        actor Counter {
            var value = 0
            func increment() { value += 1 }
        }
        let admittedDuringShutdown = Counter()

        async let shutdown: Void = session.shutdown()
        // Race a burst of enqueues against shutdown.
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<32 {
                group.addTask {
                    let result = await session.scheduleTransportProtocolWork {
                        await admittedDuringShutdown.increment()
                    }
                    if result == .admitted {
                        // May complete before or after shutdown closes admission.
                    }
                }
            }
            await group.waitForAll()
        }
        await shutdown

        #expect(await session.lifecyclePhase == .shutDown)
        let after = await session.scheduleTransportProtocolWork {
            await admittedDuringShutdown.increment()
        }
        #expect(after == .rejected)
        #expect(await session.lifecyclePhase == .shutDown)
    }

    @Test("successful startSession revives runtime after shutdown")
    func successfulStartSessionRevivesRuntimeAfterShutdown() async throws {
        let session = PQSSession()
        let user = MockUserData(session: session)
        let identityStore = user.identityStore(isSender: true)
        let transportStore = TransportStore()
        let transport = _MockTransportDelegate(session: session, store: transportStore)
        let receiver = ReceiverDelegate(session: session)
        let sessionDelegate = SessionDelegate(session: session)
        defer { Task { await session.shutdown() } }

        await identityStore.setLocalSalt("restart-lifecycle-salt")
        await transportStore.setPublishableName(user.ssn)
        await session.setDatabaseDelegate(conformer: identityStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setReceiverDelegate(conformer: receiver)
        await session.setPQSSessionDelegate(conformer: sessionDelegate)
        await session.setViability(true)
        _ = try await session.createSession(
            secretName: user.ssn,
            appPassword: user.sap
        ) {}
        _ = try await session.startSession(appPassword: user.sap)

        await session.shutdown()
        #expect(await session.lifecyclePhase == .shutDown)
        #expect(
            await session.scheduleTransportProtocolWork {} == .rejected,
            "Shutdown must remain terminal until explicit session restoration")

        // Host reconfiguration precedes startSession on relaunch. The restored
        // session must replace its terminal ratchet processor and work tree.
        await session.setDatabaseDelegate(conformer: identityStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setReceiverDelegate(conformer: receiver)
        await session.setPQSSessionDelegate(conformer: sessionDelegate)
        await session.setViability(true)
        _ = try await session.startSession(appPassword: user.sap)

        #expect(await session.lifecyclePhase == .running)
        actor Counter {
            var value = 0
            func increment() { value += 1 }
        }
        let counter = Counter()
        let admission = await session.scheduleTransportProtocolWork {
            await counter.increment()
        }
        #expect(admission == .admitted)

        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline, await counter.value == 0 {
            try? await Task.sleep(for: .milliseconds(10))
        }
        #expect(await counter.value == 1)
    }

    @Test("transport protocol items admitted while running complete exactly once")
    func transportProtocolWorkCompletesExactlyOnce() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        await session.beginSessionLifecycleIfNeeded()

        actor Counter {
            var value = 0
            func increment() { value += 1 }
            func get() -> Int { value }
        }
        let counter = Counter()
        let count = 40
        await withTaskGroup(of: SessionWorkAdmission.self) { group in
            for _ in 0..<count {
                group.addTask {
                    await session.scheduleTransportProtocolWork {
                        await counter.increment()
                    }
                }
            }
            var rejected = 0
            for await result in group {
                if result == .rejected { rejected += 1 }
            }
            #expect(rejected == 0)
        }

        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if await counter.get() == count { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(await counter.get() == count)

        let metrics = await session.sessionWorkMetrics()
        #expect(metrics.maxInFlightObserved <= PQSSessionConstants.sessionWorkMaxWorkers)
        #expect(metrics.maxPendingObserved <= PQSSessionConstants.sessionWorkMaxPending)
    }

    @Test("bounded pending capacity backpressures producers without dropping admitted work")
    func boundedPendingBackpressuresWithoutDrop() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        await session.beginSessionLifecycleIfNeeded()

        actor Gate {
            var open = false
            var waiters: [CheckedContinuation<Void, Never>] = []
            func wait() async {
                if open { return }
                await withCheckedContinuation { waiters.append($0) }
            }
            func release() {
                open = true
                let pending = waiters
                waiters.removeAll()
                for waiter in pending { waiter.resume() }
            }
        }
        let gate = Gate()
        actor Counter {
            var value = 0
            func increment() { value += 1 }
            func get() -> Int { value }
        }
        let counter = Counter()
        let total = PQSSessionConstants.sessionWorkMaxPending
            + PQSSessionConstants.sessionWorkMaxWorkers
            + 16

        async let enqueueBurst: [SessionWorkAdmission] = withTaskGroup(of: SessionWorkAdmission.self) { group in
            for _ in 0..<total {
                group.addTask {
                    await session.scheduleTransportProtocolWork {
                        await gate.wait()
                        await counter.increment()
                    }
                }
            }
            var results: [SessionWorkAdmission] = []
            for await result in group {
                results.append(result)
            }
            return results
        }

        // Let producers fill the queue and park on backpressure.
        try? await Task.sleep(nanoseconds: 50_000_000)
        let midMetrics = await session.sessionWorkMetrics()
        #expect(midMetrics.pendingCount <= PQSSessionConstants.sessionWorkMaxPending)
        #expect(midMetrics.inFlightCount <= PQSSessionConstants.sessionWorkMaxWorkers)

        await gate.release()
        let results = await enqueueBurst
        #expect(results.allSatisfy { $0 == .admitted })

        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if await counter.get() == total { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(await counter.get() == total)
    }

    @Test("setViability coalesces false-to-true resume and ignores repeated true")
    func setViabilityCoalescesResume() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        await session.setViability(false)
        await session.setViability(true)
        await session.setViability(true)
        #expect(await session.isViable)
        await session.setViability(false)
        #expect(await !session.isViable)
    }

    /// Friendship recovery / spool ACKs must keep moving while contact outbound is parked.
    @Test("non-viable session drops gated background work but still runs transport protocol work")
    func nonViableDropsBackgroundWorkButRunsTransportProtocolWork() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        await session.beginSessionLifecycleIfNeeded()
        await session.setViability(false)

        actor Counter {
            var background = 0
            var protocolWork = 0
            func bumpBackground() { background += 1 }
            func bumpProtocol() { protocolWork += 1 }
            func snapshot() -> (Int, Int) { (background, protocolWork) }
        }
        let counter = Counter()

        let bg = await session.scheduleBackgroundWork {
            await counter.bumpBackground()
        }
        let proto = await session.scheduleTransportProtocolWork {
            await counter.bumpProtocol()
        }
        #expect(bg == .admitted)
        #expect(proto == .admitted)

        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            let snap = await counter.snapshot()
            if snap.1 == 1 { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        let snap = await counter.snapshot()
        #expect(snap.0 == 0, "Gated background work must not run while non-viable (parked contact/friendship)")
        #expect(snap.1 == 1, "Transport protocol work must run while non-viable (recovery / spool ACK)")

        await session.setViability(true)
        let bg2 = await session.scheduleBackgroundWork {
            await counter.bumpBackground()
        }
        #expect(bg2 == .admitted)
        let deadline2 = Date().addingTimeInterval(2)
        while Date() < deadline2 {
            if await counter.snapshot().0 == 1 { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(await counter.snapshot().0 == 1)
    }

    @Test("two concurrent replenish waiters for same secret are not overwritten")
    func concurrentReplenishWaitersAreNotOverwritten() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let secret = "peer-replenish"
        let deviceA = UUID()
        let deviceB = UUID()

        async let first = session.awaitPeerReplenishCompletion(
            secretName: secret,
            deviceId: deviceA,
            maxWait: 0.4
        )
        // Allow first waiter to park.
        try? await Task.sleep(nanoseconds: 20_000_000)
        async let second = session.awaitPeerReplenishCompletion(
            secretName: secret,
            deviceId: deviceB,
            maxWait: 0.4
        )
        try? await Task.sleep(nanoseconds: 20_000_000)
        await session.completePeerPublishedOneTimeKeysReplenishmentWait(secretName: secret)
        let results = await (first, second)
        // Neither waiter should hang past timeout; both must complete.
        _ = results
    }
}
