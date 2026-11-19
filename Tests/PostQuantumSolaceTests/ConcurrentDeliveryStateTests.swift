//
//  ConcurrentDeliveryStateTests.swift
//  post-quantum-solace
//
//  An app keeps the `EncryptedMessage` it shows (the session hands it one in
//  `createdMessage` and `updatedMessage`) and passes it back to the session to change the
//  delivery state. Two such calls for one message can overlap: "delivered" is still being
//  written when the user opens the chat and the message becomes "read".
//
//  Only real entry points are used: `send` and `receiveMessage` put the message in Bob's
//  store, and Bob's host calls `updateMessageDeliveryState` twice at once with the one
//  instance it holds. The store is the app's SQL store in the two ways that matter: a fetch
//  is a new instance, and a write reads the row's bytes.
//
//  What it caught: `EncryptedMessage.data` was read without the instance's lock (the store
//  reading the row's bytes to write them) while the other call's `updateMessage(with:)`
//  replaced it on another thread. `--sanitize=thread` reports the race, so that is the build
//  to run this file with.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    /// `rounds` messages from Alice to Bob; for each, Bob's host marks it delivered and read.
    /// With `shareInstance` both calls run at once on the one instance the host holds;
    /// without, each call fetches its own row and they run one after the other. Returns the
    /// calls that threw and the messages whose stored row is not a readable read message.
    func deliveryStateWrites(rounds: Int, shareInstance: Bool) async throws -> (callErrors: [String], rowErrors: [String]) {
        let pair = try await connectedPair()
        await pair.aliceStore.setReturnsFreshMessageRows(true)
        await pair.bobStore.setReturnsFreshMessageRows(true)
        try await settleLanes(pair)
        await jobLoopIdle(pair.alice)
        await jobLoopIdle(pair.bob)
        await pair.alice.setLogLevel(.info)
        await pair.bob.setLogLevel(.info)
        let bob = pair.bob
        let bobStore = pair.bobStore
        let key = try await bob.getDatabaseSymmetricKey()

        var callErrors: [String] = []
        var rowErrors: [String] = []
        for round in 0..<rounds {
            let id = "state-\(round)-\(UUID().uuidString.prefix(8))"
            try await pair.alice.send(recipient: .nickname("bob"), text: "text \(id)", sharedIdOverride: id)
            try #require(await persisted(bob, id), "setup: \(id) reached Bob's store")

            func mark(_ state: DeliveryState, _ row: EncryptedMessage?) async -> String? {
                do {
                    let fetched = try await bobStore.fetchMessageIfExists(sharedId: id)
                    guard let row = row ?? fetched else { return "\(id): no row" }
                    try await bob.updateMessageDeliveryState(
                        row, deliveryState: state, messageRecipient: .nickname("alice"))
                    return nil
                } catch {
                    return "\(id) \(state): \(error)"
                }
            }
            if shareInstance {
                let held = try #require(await bobStore.fetchMessageIfExists(sharedId: id))
                async let delivered = mark(.delivered, held)
                async let read = mark(.read, held)
                callErrors += [await delivered, await read].compactMap { $0 }
                // Whichever call finished last wrote its state; the user did read it.
                if let error = await mark(.read, nil) { callErrors.append(error) }
            } else {
                for state in [DeliveryState.delivered, .read] {
                    if let error = await mark(state, nil) { callErrors.append(error) }
                }
            }

            let stored = try await bobStore.fetchMessageIfExists(sharedId: id)
            let state = await stored?.props(symmetricKey: key)?.deliveryState
            if state != .read { rowErrors.append("\(id): stored state \(String(describing: state))") }
        }

        await pair.finish()
        await shutdownSessions()
        return (callErrors, rowErrors)
    }

    @Test("two delivery-state calls at once on one message instance leave a readable row")
    func twoDeliveryStateCallsOnOneInstanceLeaveAReadableRow() async throws {
        let result = try await deliveryStateWrites(rounds: 120, shareInstance: true)
        #expect(result.callErrors.isEmpty, "\(result.callErrors.prefix(5))")
        #expect(result.rowErrors.isEmpty, "\(result.rowErrors.prefix(5))")
    }

    /// Control: the same writes one after the other, each on its own fetched row.
    @Test("delivery-state calls one after the other leave a readable row")
    func deliveryStateCallsOneAfterTheOtherLeaveAReadableRow() async throws {
        let result = try await deliveryStateWrites(rounds: 120, shareInstance: false)
        #expect(result.callErrors.isEmpty, "\(result.callErrors.prefix(5))")
        #expect(result.rowErrors.isEmpty, "\(result.rowErrors.prefix(5))")
    }
}
