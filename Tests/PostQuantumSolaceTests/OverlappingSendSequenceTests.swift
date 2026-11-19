//
//  OverlappingSendSequenceTests.swift
//  post-quantum-solace
//
//  Every stored chat message carries a sequence number taken from its conversation's message
//  count, and hosts order a conversation by it. Storing a message is: read the count, add
//  one, write it back, then number the message. `MessagePipeline` lets the next call in at
//  every await, so two messages of one conversation that are stored at the same time (two
//  sends, or a send and a received message) must still get different numbers, no increment
//  of the count may be lost, and a message stored later must get a higher number.
//
//  Only real entry points are used (`send`, `receiveMessage`) on two connected sessions, with
//  a store that keeps its own bytes per row as the app's SQL store does. Nothing forces an
//  order, so each scenario runs many rounds on one pair.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    struct SequenceOutcome: Sendable {
        /// Sequence numbers held by more than one of the test's stored messages on Alice's
        /// device, with the shared ids that hold them.
        var shared: [Int: [String]] = [:]
        /// Messages of a later round numbered at or below a message of an earlier round. A
        /// round ends when all its messages are stored, so these sort before or level with
        /// a message that was stored before them.
        var numberedTooLow: [String] = []
        /// How far Alice's stored count of the conversation moved.
        var countMoved = 0
        var sent = 0
        var received = 0
        var sendErrors: [String] = []
        var missing: [String] = []
    }

    /// Alice's stored row of her conversation with Bob.
    private func aliceConversationWithBob(_ pair: ConnectedPair) async throws -> (id: UUID, count: Int) {
        let key = try await pair.alice.getDatabaseSymmetricKey()
        for row in try await pair.aliceStore.fetchCommunications() {
            if let props = await row.props(symmetricKey: key), props.communicationType == .nickname("bob") {
                return (row.id, props.messageCount)
            }
        }
        throw PQSError.cannotFindCommunication
    }

    /// `rounds` rounds. In each, Alice sends `aliceSends` messages to Bob, from as many tasks
    /// at once (`atOnce`) or one after another, and Bob meanwhile sends `bobSends` messages
    /// to Alice one after another. Reports Alice's stored conversation afterwards.
    func sequenceNumbersAfter(
        rounds: Int, aliceSends: Int, atOnce: Bool, bobSends: Int = 0, inTurn: Bool = false
    ) async throws -> SequenceOutcome {
        let pair = try await connectedPair()
        await pair.aliceStore.setDetachesRows(true)
        await pair.bobStore.setDetachesRows(true)
        try await settleLanes(pair)
        await jobLoopIdle(pair.alice)
        await jobLoopIdle(pair.bob)
        await pair.alice.setLogLevel(.info)
        await pair.bob.setLogLevel(.info)

        var outcome = SequenceOutcome()
        let conversation = try await aliceConversationWithBob(pair)
        var roundOf: [String: Int] = [:]

        @Sendable func send(_ session: PQSSession, to peer: String, _ ids: [String]) async -> [String] {
            var errors: [String] = []
            for id in ids {
                do {
                    try await session.send(recipient: .nickname(peer), text: "text \(id)", sharedIdOverride: id)
                } catch { errors.append("\(id): \(error)") }
            }
            return errors
        }

        for round in 0..<rounds {
            let run = UUID().uuidString.prefix(8)
            let fromAlice = (0..<aliceSends).map { "\(run)-\(round)-A-\($0)" }
            let fromBob = (0..<bobSends).map { "\(run)-\(round)-B-\($0)" }
            for id in fromAlice + fromBob { roundOf[id] = round }

            // With `inTurn`, Bob's messages start after Alice's are stored on both sides.
            for (aliceIds, bobIds) in inTurn ? [(fromAlice, []), ([], fromBob)] : [(fromAlice, fromBob)] {
                outcome.sendErrors += await withTaskGroup(of: [String].self) { group in
                    if atOnce {
                        for id in aliceIds { group.addTask { await send(pair.alice, to: "bob", [id]) } }
                    } else if !aliceIds.isEmpty {
                        group.addTask { await send(pair.alice, to: "bob", aliceIds) }
                    }
                    if !bobIds.isEmpty { group.addTask { await send(pair.bob, to: "alice", bobIds) } }
                    var errors: [String] = []
                    for await some in group { errors += some }
                    return errors
                }

                // Every message is stored on both sides before anything else is sent.
                let wanted = Set(aliceIds + bobIds)
                let landed = await pollUntil(timeout: 30) {
                    let onAlice = Set(await pair.aliceStore.getAllMessages().map(\.sharedId))
                    let onBob = Set(await pair.bobStore.getAllMessages().map(\.sharedId))
                    return wanted.isSubset(of: onAlice) && wanted.isSubset(of: onBob)
                }
                if !landed {
                    let onAlice = Set(await pair.aliceStore.getAllMessages().map(\.sharedId))
                    outcome.missing += wanted.filter { !onAlice.contains($0) }
                }
                await jobLoopIdle(pair.alice)
                await jobLoopIdle(pair.bob)
            }
            outcome.sent += fromAlice.count
            outcome.received += fromBob.count
        }

        let rows = await pair.aliceStore.getAllMessages().filter {
            $0.communicationId == conversation.id && roundOf[$0.sharedId] != nil
        }
        var bySequence: [Int: [String]] = [:]
        for row in rows { bySequence[row.sequenceNumber, default: []].append(row.sharedId) }
        outcome.shared = bySequence.filter { $0.value.count > 1 }
        var highestOfEarlierRounds = Int.min
        for round in 0..<rounds {
            let ofRound = rows.filter { roundOf[$0.sharedId] == round }
            outcome.numberedTooLow += ofRound.filter { $0.sequenceNumber <= highestOfEarlierRounds }.map(\.sharedId)
            highestOfEarlierRounds = max(highestOfEarlierRounds, ofRound.map(\.sequenceNumber).max() ?? Int.min)
        }
        outcome.countMoved = try await aliceConversationWithBob(pair).count - conversation.count

        await pair.finish()
        await shutdownSessions()
        return outcome
    }

    func expectSound(_ outcome: SequenceOutcome, countMoved expected: Int) {
        #expect(outcome.sendErrors.isEmpty, "\(outcome.sendErrors)")
        #expect(outcome.missing.isEmpty, "never stored: \(outcome.missing)")
        #expect(outcome.shared.isEmpty, "\(outcome.shared.count) sequence numbers are held by more than one message, e.g. \(outcome.shared.sorted { $0.key < $1.key }.prefix(3))")
        #expect(outcome.numberedTooLow.isEmpty, "\(outcome.numberedTooLow.count) messages are numbered at or below a message stored before them, e.g. \(outcome.numberedTooLow.prefix(3))")
        #expect(outcome.countMoved == expected, "\(outcome.sent) sent and \(outcome.received) received: the count moved by \(outcome.countMoved), not \(expected)")
    }

    @Test("Four sends to one conversation at once get four different sequence numbers")
    func overlappingSendsGetDifferentSequenceNumbers() async throws {
        let outcome = try await sequenceNumbersAfter(rounds: 40, aliceSends: 4, atOnce: true)
        expectSound(outcome, countMoved: outcome.sent)
    }

    /// Control: the same messages, one send at a time.
    @Test("Control: sends to one conversation one after another get different sequence numbers")
    func sendsOneAfterAnotherGetDifferentSequenceNumbers() async throws {
        let outcome = try await sequenceNumbersAfter(rounds: 40, aliceSends: 4, atOnce: false)
        expectSound(outcome, countMoved: outcome.sent)
    }

    /// Both people send several messages in a row at the same moment: on Alice's device her
    /// sends and the storing of Bob's messages overlap. A received message moves the count
    /// by two.
    @Test("Sends and received messages stored at the same time get different sequence numbers")
    func sendsAndReceivedMessagesGetDifferentSequenceNumbers() async throws {
        let outcome = try await sequenceNumbersAfter(rounds: 150, aliceSends: 10, atOnce: false, bobSends: 10)
        expectSound(outcome, countMoved: outcome.sent + 2 * outcome.received)
    }

    /// Control: both people send, Bob's messages after Alice's are stored.
    @Test("Control: sends and received messages stored in turn get different sequence numbers")
    func sendsAndReceivedMessagesInTurnGetDifferentSequenceNumbers() async throws {
        let outcome = try await sequenceNumbersAfter(rounds: 40, aliceSends: 4, atOnce: false, bobSends: 4, inTurn: true)
        expectSound(outcome, countMoved: outcome.sent + 2 * outcome.received)
    }
}
