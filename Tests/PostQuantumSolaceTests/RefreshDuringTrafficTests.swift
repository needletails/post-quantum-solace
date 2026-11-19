//
//  RefreshDuringTrafficTests.swift
//  post-quantum-solace
//
//  The host reloads the session's caches when another process wrote the store
//  (`refreshSessionCache`). On iOS that signal also arrives while the app is connected
//  and draining its backlog, so one refresh lands in the middle of running jobs. No
//  message may be lost to it in either direction.
//
//  Only real entry points are used (`send`, `receiveMessage`, `refreshSessionCache`) and
//  nothing forces an order: each refresh fires at a random moment of the traffic. One
//  round is therefore a matter of chance, so the scenario runs many rounds on one pair.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

private actor RefreshedFlag {
    private(set) var isSet = false
    func set() { isSet = true }
}

private struct ClosedSocketError: Error {}

extension EndToEndTests {
    struct TwoWayTrafficTally: CustomStringConvertible {
        var rounds = 0
        var roundsWithLoss = 0
        /// Never transported: the sender's job ended without a frame. Each entry is the
        /// shared id and the delivery state its stored row was left in.
        var neverTransported: [String] = []
        /// Transported, and the receiver never persisted it.
        var transportedNeverPersisted: [String] = []
        var refreshErrors: [String] = []
        var sendErrors: [String] = []
        /// `pqs.recovery.unhandledInboundError` lines on either side.
        var unhandledInboundErrors = 0

        var description: String {
            "rounds=\(rounds) roundsWithLoss=\(roundsWithLoss)"
                + " neverTransported=\(neverTransported)"
                + " transportedNeverPersisted=\(transportedNeverPersisted)"
                + " unhandledInboundErrors=\(unhandledInboundErrors)"
                + " refreshErrors=\(refreshErrors) sendErrors=\(sendErrors)"
        }
    }

    /// `rounds` rounds of `messagesEachWay` messages in both directions at once on one
    /// connected pair. With `refreshing`, each session is refreshed once per round at a
    /// random moment of that round's traffic.
    func twoWayTraffic(
        rounds: Int,
        messagesEachWay: Int,
        refreshing: Bool
    ) async throws -> TwoWayTrafficTally {
        let aliceSink = RecordingAuditSink()
        let bobSink = RecordingAuditSink()
        let pair = try await connectedPair(aliceAuditSink: aliceSink, bobAuditSink: bobSink)
        // As the app's SQL store: every fetch hands out new rows.
        await pair.aliceStore.setDetachesRows(true)
        await pair.bobStore.setDetachesRows(true)
        try await settleLanes(pair)
        await jobLoopIdle(pair.alice)
        await jobLoopIdle(pair.bob)
        // Trace logging stretches every job; the proportions of a job matter here.
        await pair.alice.setLogLevel(.info)
        await pair.bob.setLogLevel(.info)

        let sides: [(session: PQSSession, store: MockIdentityStore, sink: RecordingAuditSink, peer: String, tag: String)] = [
            (pair.alice, pair.aliceStore, aliceSink, "bob", "A"),
            (pair.bob, pair.bobStore, bobSink, "alice", "B"),
        ]
        let clock = ContinuousClock()
        var tally = TwoWayTrafficTally()
        // How long one round's sends take; a refresh picks its moment inside it.
        var sendSpan = Duration.milliseconds(500)

        for round in 0..<rounds {
            let run = UUID().uuidString.prefix(8)
            let ids = sides.map { side in (0..<messagesEachWay).map { "\(run)-\(round)-\(side.tag)-\($0)" } }

            var refreshers: [Task<String?, Never>] = []
            if refreshing {
                let span = sendSpan
                for side in sides {
                    refreshers.append(Task {
                        try? await Task.sleep(for: span * Double.random(in: 0..<1))
                        do {
                            try await side.session.refreshSessionCache()
                            return nil
                        } catch {
                            return "\(side.tag): \(error)"
                        }
                    })
                }
            }

            let started = clock.now
            let senders = zip(sides, ids).map { side, sideIds in
                Task { () -> [String] in
                    var errors: [String] = []
                    for id in sideIds {
                        do {
                            try await side.session.send(
                                recipient: .nickname(side.peer), text: "text \(id)", sharedIdOverride: id)
                        } catch {
                            errors.append("\(id): \(error)")
                        }
                    }
                    return errors
                }
            }
            for sender in senders { tally.sendErrors += await sender.value }
            sendSpan = clock.now - started

            // Alice's messages land in Bob's store and Bob's in Alice's. The round ends
            // when all have, or when both job loops have stood still with nothing queued
            // for 3 s: whatever is missing then is not coming.
            func missing() async -> [[String]] {
                var out: [[String]] = []
                for (index, sideIds) in ids.enumerated() {
                    let receiver = sides[1 - index].store
                    let present = Set(await receiver.getAllMessages().map(\.sharedId))
                    out.append(sideIds.filter { !present.contains($0) })
                }
                return out
            }
            var stillSince: ContinuousClock.Instant?
            let deadline = clock.now.advanced(by: .seconds(60))
            var lost = await missing()
            while !lost.allSatisfy(\.isEmpty), clock.now < deadline {
                var still = true
                for side in sides {
                    let running = await side.session.messagePipeline.isRunning
                    let queued = await side.store.persistedJobs.count
                    if running || queued > 0 { still = false }
                }
                if still {
                    if let since = stillSince, clock.now - since >= .seconds(3) { break }
                    if stillSince == nil { stillSince = clock.now }
                } else {
                    stillSince = nil
                }
                try? await Task.sleep(for: .milliseconds(10))
                lost = await missing()
            }
            for refresher in refreshers {
                if let error = await refresher.value { tally.refreshErrors.append(error) }
            }
            await jobLoopIdle(pair.alice)
            await jobLoopIdle(pair.bob)

            tally.rounds += 1
            if !lost.allSatisfy(\.isEmpty) { tally.roundsWithLoss += 1 }
            for (index, lostIds) in lost.enumerated() {
                let sender = sides[index]
                let key = try await sender.session.getDatabaseSymmetricKey()
                let rows = await sender.store.getAllMessages()
                for id in lostIds {
                    if sender.sink.contains("pqs.send.deviceTransportOk sharedId=\(id) ") {
                        tally.transportedNeverPersisted.append(id)
                    } else {
                        let state = await rows.first { $0.sharedId == id }?.props(symmetricKey: key)?.deliveryState
                        tally.neverTransported.append("\(id): \(state.map { "\($0)" } ?? "no row")")
                    }
                }
            }
        }
        tally.unhandledInboundErrors =
            aliceSink.lines(containing: "pqs.recovery.unhandledInboundError").count
            + bobSink.lines(containing: "pqs.recovery.unhandledInboundError").count

        await pair.finish()
        await shutdownSessions()
        return tally
    }

    @Test("one cache refresh per session during two-way traffic loses no message")
    func oneRefreshDuringTwoWayTrafficLosesNoMessage() async throws {
        let tally = try await twoWayTraffic(rounds: 100, messagesEachWay: 12, refreshing: true)
        #expect(tally.refreshErrors.isEmpty && tally.sendErrors.isEmpty, "\(tally)")
        #expect(tally.neverTransported.isEmpty, "a job ended without sending its frame: \(tally)")
        #expect(tally.transportedNeverPersisted.isEmpty && tally.unhandledInboundErrors == 0,
                "a received frame was dropped: \(tally)")
    }

    /// A refresh must never wait for a whole job: the host awaits it on its connect path,
    /// and a job can sit in a transport send for as long as the socket lets it.
    @Test("a cache refresh returns from inside a job's transport send and while the queue is paused",
          .timeLimit(.minutes(1)))
    func refreshReturnsInsideAJobAndWhileTheQueueIsPaused() async throws {
        let pair = try await connectedPair()
        let alice = pair.alice
        await alice.waitForOutboundJobDrain()
        await jobLoopIdle(alice)
        await jobLoopIdle(pair.bob)

        let sharedId = "refresh-inside-send-\(UUID().uuidString)"
        let refreshedInsideSend = RefreshedFlag()
        pair.aliceTransport.duringSendMessage = { frame in
            guard frame.logicalMessageId == sharedId, await !refreshedInsideSend.isSet else { return }
            // The store-change signal handled while this job is in flight...
            try await alice.refreshSessionCache()
            await refreshedInsideSend.set()
            // ...and the send then fails as on a closed socket, which pauses the queue.
            throw ClosedSocketError()
        }
        try await alice.send(recipient: .nickname("bob"), text: "held", sharedIdOverride: sharedId)
        #expect(await refreshedInsideSend.isSet)
        try #require(await alice.messagePipeline.isPausedUntilTransportReady, "setup: the queue is paused")
        try await alice.refreshSessionCache()

        try await alice.resumeJobQueue()
        #expect(await persisted(pair.bob, sharedId, timeout: 10), "the held message is sent after the resume")

        await pair.finish()
        await shutdownSessions()
    }

    @Test("control: the same two-way traffic without a refresh loses no message")
    func twoWayTrafficWithoutRefreshLosesNoMessage() async throws {
        let tally = try await twoWayTraffic(rounds: 100, messagesEachWay: 12, refreshing: false)
        #expect(tally.sendErrors.isEmpty, "\(tally)")
        #expect(tally.neverTransported.isEmpty, "a job ended without sending its frame: \(tally)")
        #expect(tally.transportedNeverPersisted.isEmpty && tally.unhandledInboundErrors == 0,
                "a received frame was dropped: \(tally)")
    }
}
