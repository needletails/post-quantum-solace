//
//  ConcurrentSendTests.swift
//  post-quantum-solace
//
//  An app calls `send` again before the last call returned: a user sends several messages
//  quickly, or sends while a reply or a receipt is going out. `PQSSession` and
//  `MessagePipeline` are actors, and both let the next call in at every await, so the sends
//  of one conversation run interleaved, and all of them hold the one `BaseCommunication`
//  instance the session cache hands out.
//
//  Only real entry points are used (`send`, `receiveMessage`) on two connected sessions.
//  Nothing forces an order, so the scenario runs many rounds on one pair.
//
//  What it caught: `BaseCommunication.data` was read without the instance's lock (encoding
//  the row into a new message, and the store reading its bytes) while another send's
//  `updateProps` replaced it on another thread. A normal build stopped with "__DataStorage
//  deallocated with non-zero retain count" in 2 of 61 runs; `--sanitize=thread` reports the
//  race on every run, so that is the build to run this file with.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    /// `rounds` rounds in which `sendersPerSide` tasks on each side send one message each to
    /// the peer at once. Returns the shared ids that never reached the peer's store.
    func concurrentSends(rounds: Int, sendersPerSide: Int) async throws -> (lost: [String], sendErrors: [String]) {
        let pair = try await connectedPair()
        // As the app's SQL store: every write reads the row's bytes.
        await pair.aliceStore.setDetachesRows(true)
        await pair.bobStore.setDetachesRows(true)
        try await settleLanes(pair)
        await jobLoopIdle(pair.alice)
        await jobLoopIdle(pair.bob)
        // Trace logging stretches every send; the proportions of a send matter here.
        await pair.alice.setLogLevel(.info)
        await pair.bob.setLogLevel(.info)

        let sides: [(session: PQSSession, peerStore: MockIdentityStore, peer: String, tag: String)] = [
            (pair.alice, pair.bobStore, "bob", "A"),
            (pair.bob, pair.aliceStore, "alice", "B"),
        ]
        var lost: [String] = []
        var sendErrors: [String] = []

        for round in 0..<rounds {
            let run = UUID().uuidString.prefix(8)
            let ids = sides.map { side in (0..<sendersPerSide).map { "\(run)-\(round)-\(side.tag)-\($0)" } }

            sendErrors += await withTaskGroup(of: String?.self) { group in
                for (side, sideIds) in zip(sides, ids) {
                    for id in sideIds {
                        group.addTask {
                            do {
                                try await side.session.send(
                                    recipient: .nickname(side.peer), text: "text \(id)", sharedIdOverride: id)
                                return nil
                            } catch {
                                return "\(id): \(error)"
                            }
                        }
                    }
                }
                var errors: [String] = []
                for await error in group { if let error { errors.append(error) } }
                return errors
            }

            for (side, sideIds) in zip(sides, ids) {
                let wanted = Set(sideIds)
                let landed = await pollUntil(timeout: 30) {
                    wanted.isSubset(of: Set(await side.peerStore.getAllMessages().map(\.sharedId)))
                }
                if !landed {
                    let present = Set(await side.peerStore.getAllMessages().map(\.sharedId))
                    lost += sideIds.filter { !present.contains($0) }
                }
            }
            await jobLoopIdle(pair.alice)
            await jobLoopIdle(pair.bob)
        }

        await pair.finish()
        await shutdownSessions()
        return (lost, sendErrors)
    }

    @Test("four tasks a side sending to one conversation at once deliver every message")
    func concurrentSendsToOneConversationDeliverEveryMessage() async throws {
        let result = try await concurrentSends(rounds: 150, sendersPerSide: 4)
        #expect(result.sendErrors.isEmpty, "\(result.sendErrors)")
        #expect(result.lost.isEmpty, "never reached the peer's store: \(result.lost)")
    }

    /// Control: the same traffic with one task a side, so no two sends of a conversation overlap.
    @Test("one task a side sending the same traffic delivers every message")
    func oneSenderASideDeliversEveryMessage() async throws {
        let result = try await concurrentSends(rounds: 150, sendersPerSide: 1)
        #expect(result.sendErrors.isEmpty, "\(result.sendErrors)")
        #expect(result.lost.isEmpty, "never reached the peer's store: \(result.lost)")
    }
}
