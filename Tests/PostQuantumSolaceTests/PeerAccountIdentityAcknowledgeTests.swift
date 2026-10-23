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
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let oldPin = try #require(try await bobContactPin(pair))
        let aliceRowBefore = try #require(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        // Alice's account key changes; bob's view of her is trust-blocked. No frame
        // crosses here, so no NACK is pending: this pins the accept itself. The
        // crossing case (a refused frame, a NACK, the peer's orphan resend meeting
        // our rebuild) is `compromiseRotationWithCrossingTraffic`.
        try await pair.alice.rotateKeysOnPotentialCompromise()
        await #expect(throws: PQSError.peerSigningKeyOutOfSync) {
            _ = try await pair.bob.refreshIdentities(secretName: "alice", forceRefresh: true)
        }

        let proposed = try await pair.bobTransport.findConfigurationBypassingCache(for: "alice")
        #expect(proposed.signingPublicKey != oldPin, "alice's account key really changed")
        let bobRowsUnderOldIdentity = Set((try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId)).map(\.id))
        let updated = try await pair.bob.acknowledgePeerAccountIdentityChange(secretName: "alice", proposedConfiguration: proposed)

        let key = try await pair.bob.getDatabaseSymmetricKey()
        #expect(try #require(await updated.props(symmetricKey: key)).configuration.signingPublicKey == proposed.signingPublicKey)
        #expect(try await bobContactPin(pair) == proposed.signingPublicKey, "the warm contact list carries the new pin")
        let contextPin = await pair.bob.sessionContext?.peerAccountSigningKeyPins?["alice"]
        #expect(contextPin == proposed.signingPublicKey, "the context pin moved with the contact")
        let bobRowsAfter = try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId)
        #expect(bobRowsAfter.allSatisfy { !bobRowsUnderOldIdentity.contains($0.id) },
                "no lane under the old identity survives: \(bobRowsAfter.map(\.id))")

        // Signal's null message: bob's acknowledge sends alice a frame on the fresh
        // lane, so alice rebuilds her lane now, before anyone types. Without it she
        // keeps sending on the ratchet bob dropped and nothing from her decrypts
        // until bob's first send (dogfood 2026-10-24 07:11).
        #expect(await pollUntil(timeout: 20) {
            (try? await self.rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId))?
                .contains { $0.id != aliceRowBefore.id && $0.stateMLKEM != nil && !$0.archived } ?? false
        }, "alice has a new established lane for bob before she sends anything")

        // Both directions converge under the new identity. Alice's reply is the
        // responder's first send on the rebuilt lane; bob's next frame is his turn.
        // Alice's compromise rotation is still finishing in the background (one-time
        // key batch replacement, self reestablishment), so the very first frame in
        // either direction can still cross that work; convergence is what is pinned.
        let bobAccepted0 = await acceptedCount(pair.bob)
        try await pair.alice.send(recipient: .nickname("bob"), text: "alice after acknowledge")
        #expect(await pollUntil(timeout: 30) { await self.acceptedCount(pair.bob) > bobAccepted0 },
                "alice's traffic reaches bob under the new identity without bob typing first")
        let aliceAccepted0 = await acceptedCount(pair.alice)
        try await pair.bob.send(recipient: .nickname("alice"), text: "bob after acknowledge")
        #expect(await pollUntil(timeout: 30) { await self.acceptedCount(pair.alice) > aliceAccepted0 },
                "bob's traffic reaches alice under the new identity")
        await pair.finish()
    }

    @Test("a resend-unavailable notice for content that already recovered does not mark it unrecoverable")
    func staleUnavailableNoticeIsIgnored() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        let bob = pair.bob
        let envelope = "ENVELOPE-OLD", logical = "LOGICAL-1", replayEnvelope = "ENVELOPE-REPLAY"

        await bob.deferPeerResendUntilReestablished(
            sender: "alice", deviceId: pair.aliceDeviceId,
            failedMessageId: envelope, logicalSharedId: logical,
            failureClass: "crypto.bodyDecryptionFailed", notifyDelegate: false)
        // The sender's orphan replay lands under a fresh envelope and settles the request.
        let settled = await bob.settlePendingResendsForAcceptedInbound(
            sender: "alice", deviceId: pair.aliceDeviceId,
            envelopeMessageId: replayEnvelope, logicalSharedId: logical)
        #expect(settled == [envelope])

        // The sender's earlier "unavailable" answer arrives late.
        await bob.handleOutOfBandResendUnavailable(
            from: "alice", deviceId: pair.aliceDeviceId,
            unavailableEnvelopeMessageIds: [envelope])
        #expect(!(await bob.isInboundContentUnrecoverable(sender: "alice", deviceId: pair.aliceDeviceId, sharedId: envelope)),
                "recovered content must not be written off by a stale notice")

        // A notice for content that never recovered is still terminal.
        await bob.handleOutOfBandResendUnavailable(
            from: "alice", deviceId: pair.aliceDeviceId,
            unavailableEnvelopeMessageIds: ["ENVELOPE-LOST"])
        #expect(await bob.isInboundContentUnrecoverable(sender: "alice", deviceId: pair.aliceDeviceId, sharedId: "ENVELOPE-LOST"))
        await pair.finish()
    }
}
