//
//  PeerAccountIdentityAcknowledgeTests.swift
//  post-quantum-solace
//
//  Accepting a peer's new account signing key must run inside the session so the
//  warm contact list, the lanes and the context pin move together. A host that
//  rewrote the Contact in its own store left PQS reading the old pin and the user
//  saw `peerSigningKeyOutOfSync` right after tapping accept.
//

import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels
import DoubleRatchetKit

extension EndToEndTests {
    private func bobContactPin(_ pair: ConnectedPair) async throws -> Data? {
        let cache = try #require(await pair.bob.cache)
        let key = try await pair.bob.getDatabaseSymmetricKey()
        for contact in try await cache.fetchContacts() {
            if let p = await contact.props(symmetricKey: key), p.secretName == "alice" { return p.configuration.signingPublicKey }
        }
        return nil
    }

    private func rotateAliceAndWaitForBobPrompt(_ pair: ConnectedPair, trust: PeerIdentityTrustProbe) async throws {
        try await pair.alice.rotateKeysOnPotentialCompromise()
        try await pair.alice.send(recipient: .nickname("bob"), text: "alice under the new identity")
        #expect(await pollUntil(timeout: 20) { await trust.count() >= 1 }, "bob's host is told alice's account identity changed")
    }

    @Test("re-pinning only the host store leaves the forced refresh throwing peerSigningKeyOutOfSync")
    func hostStoreOnlyRepinStillThrows() async throws {
        let trust = PeerIdentityTrustProbe()
        let pair = try await connectedPair(bobTrustProbe: trust)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        try await rotateAliceAndWaitForBobPrompt(pair, trust: trust)

        // The old host flow: write the Contact straight to the store, bypassing PQS.
        let proposed = try await pair.bobTransport.findConfigurationBypassingCache(for: "alice")
        let key = try await pair.bob.getDatabaseSymmetricKey()
        let contact = try #require(try await pair.bobStore.fetchContacts().first)
        let props = try #require(await contact.props(symmetricKey: key))
        try await pair.bobStore.updateContact(try ContactModel(
            id: contact.id,
            props: .init(secretName: "alice", configuration: proposed, metadata: props.metadata),
            symmetricKey: key))

        await #expect(throws: PQSError.peerSigningKeyOutOfSync) {
            _ = try await pair.bob.refreshIdentities(secretName: "alice", forceRefresh: true)
        }
        await pair.finish()
    }

    @Test("acknowledgePeerAccountIdentityChange re-pins, drops the lanes, refreshes, and traffic flows")
    func acknowledgeThroughTheSession() async throws {
        let trust = PeerIdentityTrustProbe()
        let pair = try await connectedPair(bobTrustProbe: trust)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let oldPin = try #require(try await bobContactPin(pair))
        try await rotateAliceAndWaitForBobPrompt(pair, trust: trust)

        let proposed = try await pair.bobTransport.findConfigurationBypassingCache(for: "alice")
        #expect(proposed.signingPublicKey != oldPin, "alice's account key really changed")
        let updated = try await pair.bob.acknowledgePeerAccountIdentityChange(secretName: "alice", proposedConfiguration: proposed)

        let key = try await pair.bob.getDatabaseSymmetricKey()
        #expect(try #require(await updated.props(symmetricKey: key)).configuration.signingPublicKey == proposed.signingPublicKey)
        #expect(try await bobContactPin(pair) == proposed.signingPublicKey, "the warm contact list carries the new pin")
        let contextPin = await pair.bob.sessionContext?.peerAccountSigningKeyPins?["alice"]
        #expect(contextPin == proposed.signingPublicKey, "the context pin moved with the contact")
        let established = try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).filter { $0.stateMLKEM != nil }
        #expect(established.isEmpty, "no lane under the old identity survives: \(established.map(\.id))")

        // Both directions converge under the new identity.
        let a = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice after acknowledge")
        #expect(a.winningLaneId != nil, "\(a.candidateOrder)")
        let b = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "bob after acknowledge")
        #expect(b.winningLaneId != nil, "\(b.candidateOrder)")
        await pair.finish()
    }
}
