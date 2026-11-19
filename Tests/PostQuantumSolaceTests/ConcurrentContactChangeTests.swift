//
//  ConcurrentContactChangeTests.swift
//  post-quantum-solace
//
//  An app changes a contact's friendship state while another change to the same contact is
//  still being applied: the user blocks a contact twice in a row, or acts while the peer's
//  own change arrives. `PQSSession` lets the next call in at every await, and every call
//  gets the one `ContactModel` instance the session cache hands out.
//
//  Only real entry points are used: `requestFriendshipStateChange` on two connected
//  sessions, whose change reaches the peer through `send` and `receiveMessage` and is
//  applied there by the host's `createContact`. Nothing forces an order, so the scenario
//  runs many rounds on one pair.
//
//  What it caught: `ContactModel.data` was read without the instance's lock (the store
//  reading the row's bytes to write them) while another call's `updateProps` replaced it on
//  another thread. `--sanitize=thread` reports the race, so that is the build to run this
//  file with.
//

import BinaryCodable
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    /// `rounds` rounds in which `changersPerSide` tasks on each of `changingSides` block the
    /// one contact at once. Returns the calls that threw and, per side, why the contact row
    /// is not a readable blocked contact at the end (empty when it is).
    func concurrentFriendshipChanges(
        rounds: Int, changersPerSide: Int, bothSides: Bool
    ) async throws -> (callErrors: [String], rowErrors: [String]) {
        let pair = try await connectedPair()
        // As the app's SQL store: every write reads the row's bytes.
        await pair.aliceStore.setDetachesRows(true)
        await pair.bobStore.setDetachesRows(true)
        try await settleLanes(pair)
        await jobLoopIdle(pair.alice)
        await jobLoopIdle(pair.bob)
        await pair.alice.setLogLevel(.info)
        await pair.bob.setLogLevel(.info)

        var sides: [(session: PQSSession, store: MockIdentityStore, peer: String, contact: Contact)] = []
        for (session, store, peer) in [(pair.alice, pair.aliceStore, "bob"), (pair.bob, pair.bobStore, "alice")] {
            sides.append((session, store, peer, try await friendshipContact(on: session, peer: peer)))
        }
        let changing = bothSides ? sides : [sides[0]]

        var callErrors: [String] = []
        for round in 0..<rounds {
            callErrors += await withTaskGroup(of: String?.self) { group in
                for side in changing {
                    for _ in 0..<changersPerSide {
                        group.addTask {
                            do {
                                try await side.session.requestFriendshipStateChange(state: .blocked, contact: side.contact)
                                return nil
                            } catch {
                                return "round \(round) to \(side.peer): \(error)"
                            }
                        }
                    }
                }
                var errors: [String] = []
                for await error in group { if let error { errors.append(error) } }
                return errors
            }
            // The change travels to the peer as a message; let both sides apply it.
            await pair.alice.waitForOutboundJobDrain()
            await pair.bob.waitForOutboundJobDrain()
            await jobLoopIdle(pair.alice)
            await jobLoopIdle(pair.bob)
        }

        var rowErrors: [String] = []
        for side in sides {
            let key = try await side.session.getDatabaseSymmetricKey()
            var found = false
            for row in try await side.store.fetchContacts() {
                guard let props = await row.props(symmetricKey: key) else {
                    rowErrors.append("\(side.peer): a stored contact row does not decrypt")
                    continue
                }
                guard props.secretName == side.peer else { continue }
                found = true
                let friendship = props.metadata["friendshipMetadata"].flatMap {
                    try? BinaryDecoder().decode(FriendshipMetadata.self, from: $0)
                }
                if friendship?.myState != .blocked {
                    rowErrors.append("\(side.peer): stored state \(String(describing: friendship?.myState))")
                }
            }
            if !found { rowErrors.append("\(side.peer): no stored contact row") }
        }

        await pair.finish()
        await shutdownSessions()
        return (callErrors, rowErrors)
    }

    private func friendshipContact(on session: PQSSession, peer: String) async throws -> Contact {
        let cache = try #require(await session.cache)
        let key = try await session.getDatabaseSymmetricKey()
        for model in try await cache.fetchContacts() {
            if let props = await model.props(symmetricKey: key), props.secretName == peer {
                return try await model.makeDecryptedModel(of: Contact.self, symmetricKey: key)
            }
        }
        throw PQSError.cannotFindContact
    }

    @Test("several friendship changes to one contact at once leave a readable contact row")
    func concurrentFriendshipChangesLeaveAReadableContact() async throws {
        let result = try await concurrentFriendshipChanges(rounds: 40, changersPerSide: 3, bothSides: true)
        #expect(result.callErrors.isEmpty, "\(result.callErrors.prefix(5))")
        #expect(result.rowErrors.isEmpty, "\(result.rowErrors)")
    }

    /// Control: the same changes one at a time from one side, so no two calls on a contact overlap.
    @Test("one friendship change at a time leaves a readable contact row")
    func oneFriendshipChangeAtATimeLeavesAReadableContact() async throws {
        let result = try await concurrentFriendshipChanges(rounds: 40, changersPerSide: 1, bothSides: false)
        #expect(result.callErrors.isEmpty, "\(result.callErrors.prefix(5))")
        #expect(result.rowErrors.isEmpty, "\(result.rowErrors)")
    }
}
