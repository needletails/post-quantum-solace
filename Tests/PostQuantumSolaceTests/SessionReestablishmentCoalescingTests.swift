//
//  SessionReestablishmentCoalescingTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2026-04-17.
//
//  Copyright (c) 2026 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import BinaryCodable
import Foundation
@testable import PQSSession
import SessionModels
import Testing

/// Unit tests for sender single-flight throttling, receiver epoch/intent dedup,
/// envelope codec round-trips, and OTK-circuit/compromise-episode lifecycle linkage.
///
/// Each test creates a fresh `PQSSession` and shuts it down afterwards (the session's
/// internal `DoubleRatchetStateManager` requires explicit shutdown to avoid a deinit
/// precondition crash). The end-to-end happy path is already covered by
/// `KeyRotationTests.peerReestablishment`, which now also benefits from the throttling
/// guarantees verified here.
@Suite(.serialized)
struct SessionReestablishmentCoalescingTests {

    // MARK: - Envelope codec

    @Test("Envelope round-trips through BinaryCodable preserving all fields")
    func envelopeRoundTrip() throws {
        let targetDeviceId = UUID()
        let original = SessionReestablishmentEnvelope(
            kind: .linkedDeviceCompromiseObserved,
            intentId: UUID(),
            epoch: 42,
            emittedAt: Date(timeIntervalSince1970: 1_700_000_000),
            targetDeviceId: targetDeviceId,
            requiresPreDecryptionReset: true
        )
        let encoded = try BinaryEncoder().encode(original)
        let decoded = try BinaryDecoder().decode(SessionReestablishmentEnvelope.self, from: encoded)

        #expect(decoded.kind == original.kind)
        #expect(decoded.intentId == original.intentId)
        #expect(decoded.epoch == original.epoch)
        #expect(decoded.emittedAt == original.emittedAt)
        #expect(decoded.targetDeviceId == targetDeviceId)
        #expect(decoded.requiresPreDecryptionReset)
    }

    @Test("TransportEvent.sessionReestablishment encodes/decodes the envelope")
    func transportEventCarriesEnvelope() throws {
        let envelope = SessionReestablishmentEnvelope(
            kind: .linkedDeviceRepair,
            intentId: UUID(),
            epoch: 7
        )
        let event = TransportEvent.sessionReestablishment(envelope)
        let encoded = try BinaryEncoder().encode(event)
        let decoded = try BinaryDecoder().decode(TransportEvent.self, from: encoded)

        guard case .sessionReestablishment(let roundTrip) = decoded else {
            Issue.record("Expected .sessionReestablishment case, got \(decoded)")
            return
        }
        #expect(roundTrip == envelope)
    }

    @Test("All three SessionReestablishmentKind cases round-trip through the envelope")
    func envelopeRoundTripsEveryKind() throws {
        for kind in [SessionReestablishmentKind.peerRefresh,
                     .linkedDeviceRepair,
                     .linkedDeviceCompromiseObserved] {
            let original = SessionReestablishmentEnvelope(kind: kind, intentId: UUID(), epoch: 1)
            let encoded = try BinaryEncoder().encode(original)
            let decoded = try BinaryDecoder().decode(SessionReestablishmentEnvelope.self, from: encoded)
            #expect(decoded.kind == kind, "Round-trip lost identity for \(kind)")
        }
    }

    // MARK: - Sender single-flight

    @Test("Simultaneous peerRefresh bootstraps choose one deterministic requester")
    func simultaneousBootstrapCollisionHasSingleWinner() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let lower = try #require(UUID(uuidString: "00000000-0000-0000-0000-000000000001"))
        let higher = try #require(UUID(uuidString: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"))

        #expect(await session.localPeerRefreshBootstrapWinsCollision(
            localDeviceId: lower,
            senderDeviceId: higher,
            hasPendingLocalRequest: true))
        #expect(!(await session.localPeerRefreshBootstrapWinsCollision(
            localDeviceId: higher,
            senderDeviceId: lower,
            hasPendingLocalRequest: true)))
        #expect(!(await session.localPeerRefreshBootstrapWinsCollision(
            localDeviceId: lower,
            senderDeviceId: higher,
            hasPendingLocalRequest: false)))
        await session.shutdown()
    }

    @Test("Expired peerRefresh request cannot win a later bootstrap collision")
    func expiredPeerRefreshRequestDoesNotBlockInboundBootstrap() async throws {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let peerDeviceId = UUID()
        let expiredStart = Date().addingTimeInterval(
            -(await session.reestablishmentEpisodeTTL + 1)
        )

        #expect(await session.tryBeginReestablishmentEpisode(
            sender: "alice",
            deviceId: peerDeviceId,
            now: expiredStart))
        await session.registerExpectedPeerRefreshResponse(
            sender: "alice",
            deviceId: peerDeviceId,
            intentId: UUID())

        #expect(!(await session.hasActiveLocalPeerRefreshRequest(
            sender: "alice",
            deviceId: peerDeviceId)))
        #expect(await session.expectedPeerRefreshIntentByPeer.isEmpty)
        await session.shutdown()
    }

    @Test("Ending peerRefresh clears responder bootstrap hold")
    func endingPeerRefreshClearsResponderBootstrapHold() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let peerDeviceId = UUID()

        await session.markInboundPeerRefreshBootstrapPrepared(
            sender: "alice",
            deviceId: peerDeviceId,
            intentId: UUID())
        #expect(await session.hasRecentInboundPeerRefreshBootstrap(
            sender: "alice",
            deviceId: peerDeviceId))

        await session.endReestablishmentEpisode(
            sender: "alice",
            deviceId: peerDeviceId)

        #expect(!(await session.hasRecentInboundPeerRefreshBootstrap(
            sender: "alice",
            deviceId: peerDeviceId)))
        await session.shutdown()
    }

    @Test("Sender suppresses repeat emission to same scope within cooldown")
    func senderCooldownSuppressesDuplicateEmission() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let scope = ControlEventScope.peer(secretName: "alice")

        let first = await session.makeSessionReestablishmentEnvelope(kind: .peerRefresh, scope: scope)
        let second = await session.makeSessionReestablishmentEnvelope(kind: .peerRefresh, scope: scope)

        #expect(first != nil, "First emission should be allowed")
        #expect(second == nil, "Second emission within cooldown should be suppressed")
        await session.shutdown()
    }

    @Test("Sender can force peerRefresh re-emit inside cooldown for recovery")
    func senderForcedPeerRefreshReemitBypassesCooldown() async {
        let session = PQSSession()
        defer { Task { await session.shutdown() } }
        let scope = ControlEventScope.peer(secretName: "alice")

        let first = await session.makeSessionReestablishmentEnvelope(kind: .peerRefresh, scope: scope)
        let suppressed = await session.makeSessionReestablishmentEnvelope(kind: .peerRefresh, scope: scope)
        let forced = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: scope,
            forceReemit: true)

        #expect(first != nil)
        #expect(suppressed == nil)
        #expect(forced != nil, "Recovery failures must be able to send a fresh peerRefresh even inside cooldown")
        #expect(forced?.intentId == first?.intentId)
        #expect((forced?.epoch ?? 0) > (first?.epoch ?? 0))
        await session.shutdown()
    }

    @Test("Sender treats different scopes independently")
    func senderDifferentScopesDoNotDedupe() async {
        let session = PQSSession()

        let alice = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peer(secretName: "alice")
        )
        let bob = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peer(secretName: "bob")
        )
        let personal = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .personal
        )

        #expect(alice != nil)
        #expect(bob != nil)
        #expect(personal != nil)
        #expect(alice?.intentId != bob?.intentId)
        #expect(alice?.intentId != personal?.intentId)
        #expect(bob?.intentId != personal?.intentId)
        await session.shutdown()
    }

    @Test("Sender treats different devices of one peer independently")
    func senderDifferentPeerDevicesDoNotDedupe() async {
        let session = PQSSession()
        let deviceA = UUID()
        let deviceB = UUID()

        let firstA = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peerDevice(secretName: "alice", deviceId: deviceA))
        let duplicateA = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peerDevice(secretName: "alice", deviceId: deviceA))
        let firstB = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peerDevice(secretName: "alice", deviceId: deviceB))

        #expect(firstA?.targetDeviceId == deviceA)
        #expect(duplicateA == nil)
        #expect(firstB?.targetDeviceId == deviceB)
        #expect(firstA?.intentId != firstB?.intentId)
        await session.shutdown()
    }

    @Test("Peer refresh completion requires matching device and intent")
    func peerRefreshCompletionRequiresMatchingDeviceAndIntent() async {
        let session = PQSSession()
        let deviceA = UUID()
        let deviceB = UUID()
        let expectedIntent = UUID()

        await session.registerExpectedPeerRefreshResponse(
            sender: "alice",
            deviceId: deviceB,
            intentId: expectedIntent)

        #expect(!(await session.isExpectedPeerRefreshResponse(
            sender: "alice",
            deviceId: deviceA,
            intentId: expectedIntent)))
        #expect(!(await session.isExpectedPeerRefreshResponse(
            sender: "alice",
            deviceId: deviceB,
            intentId: UUID())))
        #expect(await session.isExpectedPeerRefreshResponse(
            sender: "alice",
            deviceId: deviceB,
            intentId: expectedIntent))

        await session.endReestablishmentEpisode(sender: "alice", deviceId: deviceB)
        #expect(!(await session.isExpectedPeerRefreshResponse(
            sender: "alice",
            deviceId: deviceB,
            intentId: expectedIntent)))
        await session.shutdown()
    }

    @Test("Sender treats different kinds independently")
    func senderDifferentKindsDoNotDedupe() async {
        let session = PQSSession()
        let scope = ControlEventScope.personal

        let compromise = await session.makeSessionReestablishmentEnvelope(
            kind: .linkedDeviceCompromiseObserved,
            scope: scope
        )
        let repair = await session.makeSessionReestablishmentEnvelope(
            kind: .linkedDeviceRepair,
            scope: scope
        )

        #expect(compromise != nil)
        #expect(repair != nil)
        #expect(compromise?.kind == .linkedDeviceCompromiseObserved)
        #expect(repair?.kind == .linkedDeviceRepair)
        await session.shutdown()
    }

    @Test("Sender per-kind epoch counter is monotonically increasing")
    func senderEpochMonotonicallyIncreases() async {
        let session = PQSSession()

        let first = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peer(secretName: "alice")
        )
        let second = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peer(secretName: "bob")
        )
        let third = await session.makeSessionReestablishmentEnvelope(
            kind: .peerRefresh,
            scope: .peer(secretName: "carol")
        )

        #expect(first?.epoch == 1)
        #expect(second?.epoch == 2)
        #expect(third?.epoch == 3)
        await session.shutdown()
    }

    @Test("clearCompromiseEpisode allows immediate re-emission after recovery")
    func clearCompromiseEpisodeReleasesCooldown() async {
        let session = PQSSession()
        let scope = ControlEventScope.personal

        let first = await session.makeSessionReestablishmentEnvelope(
            kind: .linkedDeviceCompromiseObserved,
            scope: scope
        )
        #expect(first != nil)

        // Without clearing, would be suppressed for 5 minutes.
        let blocked = await session.makeSessionReestablishmentEnvelope(
            kind: .linkedDeviceCompromiseObserved,
            scope: scope
        )
        #expect(blocked == nil)

        await session.clearCompromiseEpisode()

        let afterClear = await session.makeSessionReestablishmentEnvelope(
            kind: .linkedDeviceCompromiseObserved,
            scope: scope
        )
        #expect(afterClear != nil, "After clearCompromiseEpisode, the next event must emit")
        #expect(afterClear?.intentId != first?.intentId, "Cleared episode should mint a fresh intentId")
        await session.shutdown()
    }

    @Test("clearCompromiseEpisode resets OTK upload circuit breaker flags")
    func clearCompromiseEpisodeClearsCircuitBreaker() async {
        let session = PQSSession()
        await session.setOTKBreakerForTesting(open: true)

        await session.clearCompromiseEpisode()

        let stillOpen = await session.otkUploadCircuitOpen
        #expect(stillOpen == false)
        let openedAt = await session.otkUploadCircuitOpenedAt
        #expect(openedAt == nil)
        await session.shutdown()
    }

    @Test("clearCompromiseEpisode does not silently wipe peerRefresh episodes")
    func clearCompromiseEpisodePreservesPeerRefresh() async {
        let session = PQSSession()
        let peerScope = ControlEventScope.peer(secretName: "bob")

        let peer = await session.makeSessionReestablishmentEnvelope(kind: .peerRefresh, scope: peerScope)
        #expect(peer != nil)

        await session.clearCompromiseEpisode()

        let peerAfter = await session.makeSessionReestablishmentEnvelope(kind: .peerRefresh, scope: peerScope)
        #expect(peerAfter == nil, "peerRefresh episode must remain in cooldown after clearCompromiseEpisode")
        await session.shutdown()
    }

    // MARK: - Receiver coalescing

    @Test("Receiver dedups same intentId across multiple deliveries")
    func receiverIntentDedup() async {
        let session = PQSSession()
        let senderDeviceId = UUID()
        let envelope = SessionReestablishmentEnvelope(
            kind: .linkedDeviceCompromiseObserved,
            intentId: UUID(),
            epoch: 5
        )

        let first = await session.recordReceivedSessionReestablishment(
            envelope: envelope,
            senderDeviceId: senderDeviceId
        )
        let second = await session.recordReceivedSessionReestablishment(
            envelope: envelope,
            senderDeviceId: senderDeviceId
        )
        let third = await session.recordReceivedSessionReestablishment(
            envelope: envelope,
            senderDeviceId: senderDeviceId
        )

        #expect(first == .process)
        #expect(second == .skipDuplicate)
        #expect(third == .skipDuplicate)
        await session.shutdown()
    }

    @Test("Receiver drops strictly older epoch from same sender + kind")
    func receiverDropsStaleEpoch() async {
        let session = PQSSession()
        let senderDeviceId = UUID()

        let high = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 10
        )
        let low = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 3
        )

        let firstResult = await session.recordReceivedSessionReestablishment(
            envelope: high,
            senderDeviceId: senderDeviceId
        )
        let staleResult = await session.recordReceivedSessionReestablishment(
            envelope: low,
            senderDeviceId: senderDeviceId
        )

        #expect(firstResult == .process)
        #expect(staleResult == .skipStale)
        await session.shutdown()
    }

    @Test("Receiver allows higher epoch through after older one was processed")
    func receiverAcceptsNewerEpoch() async {
        let session = PQSSession()
        let senderDeviceId = UUID()

        let low = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 1
        )
        let high = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 4
        )

        let firstResult = await session.recordReceivedSessionReestablishment(
            envelope: low,
            senderDeviceId: senderDeviceId
        )
        let nextResult = await session.recordReceivedSessionReestablishment(
            envelope: high,
            senderDeviceId: senderDeviceId
        )

        #expect(firstResult == .process)
        #expect(nextResult == .process)
        await session.shutdown()
    }

    @Test("Receiver allows higher epoch through for same intent re-emits")
    func receiverAcceptsSameIntentNewerEpochReemit() async {
        let session = PQSSession()
        let senderDeviceId = UUID()
        let intentId = UUID()

        let first = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: intentId,
            epoch: 1
        )
        let reemit = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: intentId,
            epoch: 4
        )

        let firstResult = await session.recordReceivedSessionReestablishment(
            envelope: first,
            senderDeviceId: senderDeviceId
        )
        let reemitResult = await session.recordReceivedSessionReestablishment(
            envelope: reemit,
            senderDeviceId: senderDeviceId
        )

        #expect(firstResult == .process)
        #expect(reemitResult == .process)
        await session.shutdown()
    }

    @Test("Receiver can retry a reestablishment event after partial handling failure")
    func receiverCanRetryAfterPartialHandlingFailure() async {
        let session = PQSSession()
        let senderDeviceId = UUID()
        let envelope = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 1)

        let first = await session.recordReceivedSessionReestablishment(
            envelope: envelope,
            senderDeviceId: senderDeviceId)
        await session.forgetReceivedSessionReestablishment(
            envelope: envelope,
            senderDeviceId: senderDeviceId)
        let retry = await session.recordReceivedSessionReestablishment(
            envelope: envelope,
            senderDeviceId: senderDeviceId)

        #expect(first == .process)
        #expect(retry == .process, "Failed peerRefresh handling should allow the same event to be retried")
        await session.shutdown()
    }

    @Test("Receiver treats same epoch+different intentId as duplicate")
    func receiverTreatsSameEpochAsDuplicate() async {
        let session = PQSSession()
        let senderDeviceId = UUID()

        let a = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 7
        )
        let b = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 7
        )

        let r1 = await session.recordReceivedSessionReestablishment(envelope: a, senderDeviceId: senderDeviceId)
        let r2 = await session.recordReceivedSessionReestablishment(envelope: b, senderDeviceId: senderDeviceId)
        #expect(r1 == .process)
        #expect(r2 == .skipDuplicate)
        await session.shutdown()
    }

    @Test("Receiver treats different (senderDeviceId, kind) tuples independently")
    func receiverScopesByDeviceAndKind() async {
        let session = PQSSession()
        let aliceDevice = UUID()
        let bobDevice = UUID()

        let envelope = SessionReestablishmentEnvelope(
            kind: .peerRefresh,
            intentId: UUID(),
            epoch: 1
        )

        let alicePeer = await session.recordReceivedSessionReestablishment(envelope: envelope, senderDeviceId: aliceDevice)
        let bobPeer = await session.recordReceivedSessionReestablishment(envelope: envelope, senderDeviceId: bobDevice)
        let aliceCompromise = await session.recordReceivedSessionReestablishment(
            envelope: SessionReestablishmentEnvelope(kind: .linkedDeviceCompromiseObserved, intentId: UUID(), epoch: 1),
            senderDeviceId: aliceDevice
        )

        #expect(alicePeer == .process)
        #expect(bobPeer == .process, "Different sender device must not be deduped against alice")
        #expect(aliceCompromise == .process, "Different kind must not be deduped against peerRefresh")
        await session.shutdown()
    }

    @Test("Receiver collapses 30-message offline backlog burst to a single process")
    func receiverCollapsesBacklogBurst() async {
        // This is the user-reported scenario: alice CHILD pushes 30 compromise events to
        // alice MASTER while master is offline. When master comes back online, the
        // ordered drain hands every message to handleStreamMessage in turn. Without
        // dedup, the delegate fires 30 times. With dedup, exactly one fires.
        let session = PQSSession()
        let aliceChildDevice = UUID()
        let intentId = UUID()
        let epoch: UInt64 = 12

        var processCount = 0
        var skipDuplicateCount = 0

        for _ in 0 ..< 30 {
            let envelope = SessionReestablishmentEnvelope(
                kind: .linkedDeviceCompromiseObserved,
                intentId: intentId,
                epoch: epoch,
                emittedAt: Date()
            )
            switch await session.recordReceivedSessionReestablishment(
                envelope: envelope,
                senderDeviceId: aliceChildDevice
            ) {
            case .process: processCount += 1
            case .skipDuplicate: skipDuplicateCount += 1
            case .skipStale:
                Issue.record("Backlog burst should never produce skipStale")
            }
        }

        #expect(processCount == 1, "Exactly one delivery from a single-episode backlog should be processed")
        #expect(skipDuplicateCount == 29)
        await session.shutdown()
    }

    @Test("Receiver still acts on a legacy (epoch=0) event the first time it sees one")
    func receiverHandlesLegacyEnvelopeOnce() async {
        // Mid-rollout: a legacy sender ships a bare-kind payload that decodes as
        // an envelope with `epoch=0` and `intentId=nil`. Receiver must process it the
        // first time and then dedupe duplicates by epoch=0 thereafter.
        let session = PQSSession()
        let legacy = SessionReestablishmentEnvelope(kind: .peerRefresh, intentId: nil, epoch: 0)
        let senderDeviceId = UUID()

        let first = await session.recordReceivedSessionReestablishment(envelope: legacy, senderDeviceId: senderDeviceId)
        let second = await session.recordReceivedSessionReestablishment(envelope: legacy, senderDeviceId: senderDeviceId)

        #expect(first == .process)
        // With epoch==0 on both sides we don't have ordering info; we still allow
        // the second through because we cannot prove it's a duplicate of the first.
        // This is the safer trade-off pre-rollout: legacy events keep working; new
        // envelope-aware events get the strong dedup.
        #expect(second == .process)
        await session.shutdown()
    }

    // MARK: - Forced identity refresh throttling

    @Test("shouldForceIdentityRefresh allows first call and throttles bursts")
    func identityRefreshThrottle() async {
        let session = PQSSession()

        let first = await session.shouldForceIdentityRefresh(secretName: "alice")
        let second = await session.shouldForceIdentityRefresh(secretName: "alice")
        let third = await session.shouldForceIdentityRefresh(secretName: "alice")
        let differentSender = await session.shouldForceIdentityRefresh(secretName: "bob")

        #expect(first == true)
        #expect(second == false)
        #expect(third == false)
        #expect(differentSender == true, "Per-sender throttle must not block other senders")
        await session.shutdown()
    }
}

// MARK: - Test-only helpers

extension PQSSession {
    /// Test-only helper for forcing the OTK upload circuit breaker into the open state
    /// without going through the asynchronous recovery scheduler.
    /// Lives in this test target via `@testable import PQSSession` and is never compiled
    /// into release builds outside of Tests.
    func setOTKBreakerForTesting(open: Bool) {
        otkUploadCircuitOpen = open
        otkUploadCircuitOpenedAt = open ? Date() : nil
    }
}
