//
//  PeerOneTimeKeyBindingTests.swift
//  post-quantum-solace
//
//  A peer's one-time key reaches a lane only through `consume_otks`: the key the
//  server hands out leaves the pool, so no second sender can be served it. Binding
//  from the published list left the key there for the next consumer, and a forced
//  refresh rewrote a key the row had already consumed. The one logged candidate is
//  master key B8124F54, cited by first frames from two peers on 2026-10-27 (rows
//  4DE52D05 and AE7F8182); the logs cannot tell this path from a server lost update.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels

extension EndToEndTests {
    /// Bob's fresh state-less row for alice's device, replacing the settled one.
    private func freshRow(_ pair: ConnectedPair, consumingOneTimeKeys: Bool) async throws -> UUID {
        try await settleLanes(pair)
        return try await pair.bob.resetSessionIdentityForFreshSession(
            secretName: "alice",
            deviceId: pair.aliceDeviceId,
            sendOneTimeIdentities: consumingOneTimeKeys,
            reason: "test",
            reuseStateLessRepairLane: false).id
    }

    private func bobsRow(_ pair: ConnectedPair, _ id: UUID) async throws -> SessionIdentity.UnwrappedProps {
        let row = try #require(try await pair.bob.cache?.fetchSessionIdentities().first { $0.id == id })
        return try #require(await row.props(symmetricKey: try await pair.bob.getDatabaseSymmetricKey()))
    }

    @Test("a forced refresh keeps a consumed key on a state-less row")
    func forcedRefreshKeepsAConsumedKey() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        let row = try await freshRow(pair, consumingOneTimeKeys: true)
        let consumed = try await bobsRow(pair, row)
        let curveKey = try #require(consumed.oneTimePublicKey)

        _ = try await pair.bob.refreshIdentities(secretName: "alice", forceRefresh: true)

        let refreshed = try await bobsRow(pair, row)
        #expect(refreshed.oneTimePublicKey?.id == curveKey.id)
        #expect(refreshed.mlKEMPublicKey.id == consumed.mlKEMPublicKey.id)
        await pair.finish()
    }

    /// Rotation never replaces a row, and a peer keeps one prior final key, so a
    /// dormant row left on the old key would fail on every first send.
    @Test("a forced refresh moves an OTK-less state-less row to the peer's current final ML-KEM key")
    func forcedRefreshMovesARepairRowToTheCurrentFinalKey() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        let row = try await freshRow(pair, consumingOneTimeKeys: false)
        let staleKey = try await finalMLKEMKeyId(pair.alice)
        #expect(try await bobsRow(pair, row).mlKEMPublicKey.id == staleKey)

        for _ in 1...2 {
            try await makeRotationDue(on: pair.alice)
            #expect(try await pair.alice.rotateMLKEMKeysIfNeeded())
        }
        let currentKey = try await finalMLKEMKeyId(pair.alice)
        #expect(currentKey != staleKey)

        _ = try await pair.bob.refreshIdentities(secretName: "alice", forceRefresh: true)

        let refreshed = try await bobsRow(pair, row)
        #expect(refreshed.mlKEMPublicKey.id == currentKey)
        #expect(refreshed.oneTimePublicKey == nil, "a repair row stays without a one-time key")
        await pair.finish()
    }

    @Test("a notify binds its key through consume, and the next consumer gets a different key")
    func notifyBindsThroughConsume() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        let row = try await freshRow(pair, consumingOneTimeKeys: false)
        // Alice never sees the notify, so only bob's bind can change her pool.
        pair.bobTransport.shouldDeliver = { $0.recipient != "alice" }

        #expect(try await pair.bob.deliverPeerHandshakeNotifyBeforeOutboundSenderInit(secretName: "alice"))

        let bound = try #require(try await bobsRow(pair, row).oneTimePublicKey)
        let next = try await pair.bobTransport.fetchOneTimeKeys(
            for: "alice",
            deviceId: pair.aliceDeviceId.uuidString)
        #expect(try #require(next.x25519).id != bound.id)
        await pair.finish()
    }
}
