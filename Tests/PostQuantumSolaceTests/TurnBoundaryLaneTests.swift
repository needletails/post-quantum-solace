//
//  TurnBoundaryLaneTests.swift
//  post-quantum-solace
//
//  The per-turn hybrid ratchet (X25519 + ML-KEM-1024 on every turn) is what
//  re-keys an established lane. These tests pin the properties the design
//  claims at the PQS layer: a lost boundary frame does not stall a turn, frames
//  crossing a turn in either direction decrypt on the established lane, a
//  compromise rotation with traffic in flight converges without losing content,
//  and the per-frame wire overhead is recorded.
//

import BinaryCodable
import Foundation
import Testing
@testable import PQSSession
@testable import SessionModels
import DoubleRatchetKit

extension EndToEndTests {
    /// Holds content frames from `transport` addressed to `recipient` until released.
    private func holdContent(on transport: _MockTransportDelegate, to recipient: String, in held: HeldFrames) {
        transport.shouldDeliver = { received in
            guard received.recipient == recipient, received.isContentMessage else { return true }
            await held.hold(received)
            return false
        }
    }

    @Test("a lost boundary frame does not stall the turn: later frames of the new chain complete the step")
    func lostBoundaryFrameCompletesTurnFromLaterFrame() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let aliceRow = try #require(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        let bobRow = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first)

        // Alice takes a turn, so bob's next send is a sending ratchet step and
        // its first frame is the boundary frame of a new chain.
        _ = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice turn")

        let held = HeldFrames()
        holdContent(on: pair.bobTransport, to: "alice", in: held)
        for i in 1...3 {
            try await pair.bob.send(recipient: .nickname("alice"), text: "bob new chain \(i)")
        }
        #expect(await pollUntil(timeout: 20) { await held.count == 3 })
        pair.bobTransport.shouldDeliver = nil
        let frames = await held.take()
        let accepted0 = await acceptedCount(pair.alice)

        // The boundary frame is lost for now: the second frame arrives first.
        pair.bobTransport.continuation?.yield(frames[1])
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.alice) >= accepted0 + 1 },
                "alice completes the receiving step from the second frame of bob's new chain")
        pair.bobTransport.continuation?.yield(frames[2])
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.alice) >= accepted0 + 2 })
        // The boundary frame arrives late and decrypts from the stashed key.
        pair.bobTransport.continuation?.yield(frames[0])
        #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.alice) >= accepted0 + 3 },
                "the late boundary frame decrypts from the skipped-key stash")

        expectSameLane(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId), aliceRow, "alice's lane")
        expectSameLane(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId), bobRow, "bob's lane")
        #expect(await pair.controls.reestablishments == 0, "no recovery was needed")

        let reply = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice after the lost boundary")
        #expect(reply.winningLaneId == bobRow.id && reply.attempts.count == 1, "\(reply.candidateOrder)")
        await pair.finish()
    }

    @Test("frames crossing a ratchet turn in both directions decrypt on the established lane")
    func framesCrossingATurnBothWays() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)
        let aliceRow = try #require(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).first)
        let bobRow = try #require(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).first)

        // Two rounds: the turn frame lands first, then the old-chain frames land first.
        for turnFirst in [true, false] {
            let held = HeldFrames()
            holdContent(on: pair.aliceTransport, to: "bob", in: held)
            holdContent(on: pair.bobTransport, to: "alice", in: held)
            // Alice's send is a turn (she holds bob's latest ratchet key); bob's two
            // sends ride his current chain because he has not seen her turn yet.
            try await pair.alice.send(recipient: .nickname("bob"), text: "alice turn \(turnFirst)")
            try await pair.bob.send(recipient: .nickname("alice"), text: "bob old chain 1 \(turnFirst)")
            try await pair.bob.send(recipient: .nickname("alice"), text: "bob old chain 2 \(turnFirst)")
            #expect(await pollUntil(timeout: 20) { await held.count == 3 })
            pair.aliceTransport.shouldDeliver = nil
            pair.bobTransport.shouldDeliver = nil

            let frames = await held.take()
            let toBob = frames.filter { $0.recipient == "bob" }
            let toAlice = frames.filter { $0.recipient == "alice" }
            let aliceAccepted0 = await acceptedCount(pair.alice)
            let bobAccepted0 = await acceptedCount(pair.bob)
            if turnFirst {
                for frame in toBob { pair.aliceTransport.continuation?.yield(frame) }
                #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.bob) >= bobAccepted0 + 1 })
                for frame in toAlice { pair.bobTransport.continuation?.yield(frame) }
            } else {
                for frame in toAlice { pair.bobTransport.continuation?.yield(frame) }
                #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.alice) >= aliceAccepted0 + 2 })
                for frame in toBob { pair.aliceTransport.continuation?.yield(frame) }
            }
            #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.alice) >= aliceAccepted0 + 2 },
                    "bob's old-chain frames decrypt after alice's turn (turnFirst=\(turnFirst))")
            #expect(await pollUntil(timeout: 20) { await self.acceptedCount(pair.bob) >= bobAccepted0 + 1 },
                    "alice's turn frame decrypts while bob's frames were in flight (turnFirst=\(turnFirst))")

            // Live traffic afterwards: bob's reply is his turn, alice's is hers.
            let b = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "bob live \(turnFirst)")
            let a = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice live \(turnFirst)")
            #expect(b.winningLaneId == aliceRow.id && b.attempts.count == 1, "\(b.candidateOrder)")
            #expect(a.winningLaneId == bobRow.id && a.attempts.count == 1, "\(a.candidateOrder)")
        }

        expectSameLane(try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId), aliceRow, "alice's lane")
        expectSameLane(try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId), bobRow, "bob's lane")
        #expect(await pair.controls.reestablishments == 0, "no recovery was needed")
        await pair.finish()
    }

    /// What the host does when the user accepts a peer's new account identity.
    private func acceptPeerIdentity(on session: PQSSession, peer: String, via transport: _MockTransportDelegate) async throws {
        let proposed = try await transport.findConfigurationBypassingCache(for: peer)
        _ = try await session.acknowledgePeerAccountIdentityChange(secretName: peer, proposedConfiguration: proposed)
    }

    @Test("a compromise rotation with frames in flight is trust-blocked until the host re-trusts, then converges")
    func compromiseRotationWithCrossingTraffic() async throws {
        let trust = PeerIdentityTrustProbe()
        let unrecoverable = OutboundUnrecoverableProbe()
        let pair = try await connectedPair(bobTrustProbe: trust, aliceUnrecoverableProbe: unrecoverable)
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        // Bob's frames leave before alice rotates and land after.
        let held = HeldFrames()
        holdContent(on: pair.bobTransport, to: "alice", in: held)
        let inFlight = 5
        for i in 1...inFlight {
            try await pair.bob.send(recipient: .nickname("alice"), text: "bob before rotation \(i)")
        }
        #expect(await pollUntil(timeout: 20) { await held.count == inFlight })
        // Count from before the rotation, so the check below covers its announcement.
        await jobLoopIdle(pair.bob)
        let bobAccepted0 = await acceptedCount(pair.bob)

        try await pair.alice.rotateKeysOnPotentialCompromise()
        #expect(await pollUntil(timeout: 20) { await pair.controls.reestablishments >= 1 },
                "the rotation announces itself to the peer")

        // A compromise rotation changes alice's account signing key. Bob pins that
        // key (TOFU), so frames under the new identity are refused and the host is
        // told, exactly like a changed safety number that the user must accept.
        // Alice's next frame is held until the host has accepted.
        let afterRotation = "alice-after-rotation-\(UUID().uuidString)"
        let heldAfterRotation = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            guard received.recipient == "bob", received.logicalMessageId == afterRotation else { return true }
            await heldAfterRotation.hold(received)
            return false
        }
        try await pair.alice.send(recipient: .nickname("bob"), text: "alice right after rotation", sharedIdOverride: afterRotation)
        #expect(await pollUntil(timeout: 20) { await heldAfterRotation.count == 1 })
        pair.aliceTransport.shouldDeliver = nil
        #expect(await pollUntil(timeout: 20) { await trust.count() >= 1 },
                "bob's host is told that alice's account identity changed")
        // The announcement is the only frame under the new identity bob has seen;
        // let its job finish before counting.
        await jobLoopIdle(pair.bob)
        let bobAcceptedWhileBlocked = await acceptedCount(pair.bob)
        #expect(bobAcceptedWhileBlocked == bobAccepted0, "nothing under the new identity is accepted before re-trust")

        // The host accepts the new identity with bob idle and alice's frame still held.
        // An inbound lane rollback during the accept's identity refresh is a known race
        // this test does not cover (SessionCache.updateSessionIdentity writes by an
        // index read before an await).
        try await acceptPeerIdentity(on: pair.bob, peer: "alice", via: pair.bobTransport)

        // Alice's held frame lands now. It belongs to the lane she opened at her
        // rotation, which bob refused, so bob cannot open it (missing one-time key):
        // he resets and sends her a second lane-rebuild frame while she is answering
        // the one his acknowledge sent, then asks her to resend the frame. Its first
        // delivery fails; the lanes converge through recovery.
        for frame in await heldAfterRotation.take() { pair.aliceTransport.continuation?.yield(frame) }

        // Wait for each live frame by its id: the recovery frames above land in the
        // same window, and if one ends the wait, bob's send crosses alice's in flight.
        pair.bobTransport.shouldDeliver = nil
        let aliceLive = "alice-after-retrust-\(UUID().uuidString)"
        try await pair.alice.send(recipient: .nickname("bob"), text: "alice after re-trust", sharedIdOverride: aliceLive)
        #expect(await persisted(pair.bob, aliceLive), "alice's traffic reaches bob under the new identity")
        let bobLive = "bob-after-retrust-\(UUID().uuidString)"
        try await pair.bob.send(recipient: .nickname("alice"), text: "bob after re-trust", sharedIdOverride: bobLive)
        #expect(await persisted(pair.alice, bobLive), "bob's traffic reaches alice under the new identity")

        // Bob's identity did not change, so the frames he sent before alice's
        // rotation still decrypt on alice when they finally land.
        let aliceAccepted0 = await acceptedCount(pair.alice)
        for frame in await held.take() { pair.bobTransport.continuation?.yield(frame) }
        let landed = await pollUntil(timeout: 30) { await self.acceptedCount(pair.alice) >= aliceAccepted0 + inFlight }
        let count = await acceptedCount(pair.alice) - aliceAccepted0
        #expect(landed, "frames bob sent before alice's rotation decrypt on alice; got \(count) of \(inFlight)")

        // Record what happened to the frame alice sent while bob had not re-trusted.
        try? await Task.sleep(for: .seconds(3))
        let lost = await unrecoverable.recorded()
        let bobAcceptedAfter = await acceptedCount(pair.bob) - bobAccepted0
        print("""
            🔵 Compromise rotation with crossing traffic
               alice's frame sent before bob re-trusted: outboundUnrecoverable=\(lost.count) \(lost.map(\.reason))
               bob accepted \(bobAcceptedAfter) frame(s) after re-trust (1 is the live frame; 2 means the refused frame was replayed)
            """)

        // Late frames from the lane bob dropped must not steer alice's next send
        // back onto it: live traffic after they land still decrypts first try.
        let controlsBefore = await pair.controls.reestablishments
        let a2 = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "alice after late frames")
        #expect(a2.winningLaneId != nil && a2.attempts.count == 1, "alice's send after bob's late frames lands first try: \(a2.candidateOrder)")
        let b2 = try await sendAndAwaitInbound(from: pair.bob, to: "alice", on: pair.alice, text: "bob after late frames")
        #expect(b2.winningLaneId != nil && b2.attempts.count == 1, "\(b2.candidateOrder)")
        #expect(await pair.controls.reestablishments == controlsBefore, "no recovery after the late frames")

        let aliceActive = try await rows(on: pair.alice, peer: "bob", deviceId: pair.bobDeviceId).filter { !$0.archived }
        let bobActive = try await rows(on: pair.bob, peer: "alice", deviceId: pair.aliceDeviceId).filter { !$0.archived }
        // Bob reset cleanly: one active lane. Alice may still hold the orphan-resend
        // recovery lane beside the proven one until that wave closes (activation
        // deliberately keeps a live recovery lane); traffic above proved it is not
        // steering her sends.
        #expect(bobActive.count == 1, "bob keeps one active lane for alice: \(bobActive.map(\.id))")
        #expect(aliceActive.count <= 2, "alice: proven lane plus at most the open recovery lane: \(aliceActive.map(\.id))")
        await pair.finish()
    }

    @Test("per-frame wire overhead of the hybrid ratchet is recorded")
    func perFrameWireOverhead() async throws {
        let pair = try await connectedPair()
        defer { Task { await shutdownSessions() } }
        try await settleLanes(pair)

        let captured = HeldFrames()
        pair.aliceTransport.shouldDeliver = { received in
            if received.recipient == "bob", received.isContentMessage { await captured.hold(received) }
            return true
        }
        _ = try await sendAndAwaitInbound(from: pair.alice, to: "bob", on: pair.bob, text: "size probe")
        pair.aliceTransport.shouldDeliver = nil

        let frame = try #require(await captured.take().first)
        let signed = try #require(frame.message.signed)
        let ratchetMessage = try BinaryDecoder().decode(RatchetMessage.self, from: signed.data)
        let wire = try BinaryEncoder().encode(frame.message).count
        let header = ratchetMessage.header
        print("""
            🔵 Wire overhead for a 10-byte text after the handshake
               signed frame=\(wire) B, ratchet message=\(signed.data.count) B
               outer header: identity ML-KEM pub=\(header.remoteMLKEMPublicKey.rawRepresentation.count) B, \
            PQXDH ct=\(header.messageCiphertext.count) B, header ct=\(header.headerCiphertext.count) B
               inner header (AEAD, per-turn X25519 pub + ML-KEM-1024 pub + ML-KEM ct)=\(header.encrypted.count) B
               body ciphertext=\(ratchetMessage.ciphertext.count) B
            """)
        #expect(wire < 16_384, "one frame must stay well inside the multipart budget: \(wire) B")
        await pair.finish()
    }
}
