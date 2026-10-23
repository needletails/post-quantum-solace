//
//  InboundLaneSelectionTests.swift
//  post-quantum-solace
//
//  TDD: InboundLaneSelectionPolicy (header-match ordering, restore gate) and
//  InboundNegativeDecryptCache (per-frame negative cache for redelivered ciphertext).
//

import DoubleRatchetKit
import Foundation
import Testing
@testable import PQSSession

@Suite("Inbound lane selection policy")
struct InboundLaneSelectionTests {
    private struct TestError: Error, Equatable {
        let tag: String
    }

    // MARK: - Header match ordering

    @Test("full header match outranks partial and no match")
    func headerMatchRanking() {
        let ltk = Data(repeating: 0x11, count: 32)
        let otk = UUID()
        let kem = UUID()
        let full = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: ltk, laneOneTimeKeyId: otk, laneMLKEMKeyId: kem,
            headerLongTermPublicKey: ltk, headerOneTimeKeyId: otk, headerMLKEMKeyId: kem)
        let ltkOnly = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: ltk, laneOneTimeKeyId: UUID(), laneMLKEMKeyId: UUID(),
            headerLongTermPublicKey: ltk, headerOneTimeKeyId: otk, headerMLKEMKeyId: kem)
        let none = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: Data(repeating: 0x22, count: 32), laneOneTimeKeyId: nil, laneMLKEMKeyId: UUID(),
            headerLongTermPublicKey: ltk, headerOneTimeKeyId: otk, headerMLKEMKeyId: kem)
        #expect(full.longTermKeyMatches && full.oneTimeKeyIdMatches && full.mlKEMKeyIdMatches)
        #expect(full.rank > ltkOnly.rank)
        #expect(ltkOnly.rank > none.rank)
        #expect(none.rank == 0)
    }

    @Test("long-term key match outranks one-time and ML-KEM id matches combined")
    func longTermKeyDominates() {
        let ltk = Data(repeating: 0x11, count: 32)
        let otk = UUID()
        let kem = UUID()
        let ltkOnly = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: ltk, laneOneTimeKeyId: nil, laneMLKEMKeyId: UUID(),
            headerLongTermPublicKey: ltk, headerOneTimeKeyId: otk, headerMLKEMKeyId: kem)
        let idsOnly = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: Data(repeating: 0x22, count: 32), laneOneTimeKeyId: otk, laneMLKEMKeyId: kem,
            headerLongTermPublicKey: ltk, headerOneTimeKeyId: otk, headerMLKEMKeyId: kem)
        #expect(ltkOnly.rank > idsOnly.rank)
    }

    @Test("absent one-time key on both sides counts as a match, as the blank dedupe does")
    func nilOneTimeKeyMatchesNil() {
        let ltk = Data(repeating: 0x11, count: 32)
        let match = InboundLaneSelectionPolicy.headerMatch(
            laneLongTermPublicKey: ltk, laneOneTimeKeyId: nil, laneMLKEMKeyId: nil,
            headerLongTermPublicKey: ltk, headerOneTimeKeyId: nil, headerMLKEMKeyId: nil)
        #expect(match.oneTimeKeyIdMatches)
        #expect(match.mlKEMKeyIdMatches)
    }

    @Test("ordering is a stable partition: higher rank first, original order among equals")
    func orderingIsStable() {
        let items: [(name: String, rank: Int)] = [
            ("a0", 0), ("b4", 4), ("c0", 0), ("d6", 6), ("e4", 4), ("f0", 0),
        ]
        let ordered = InboundLaneSelectionPolicy.orderedByHeaderMatch(items, rank: \.rank)
        #expect(ordered.map(\.name) == ["d6", "b4", "e4", "a0", "c0", "f0"])
    }

    @Test("ordering leaves an all-equal list untouched")
    func orderingPreservesEqualRanks() {
        let items = ["newest", "older", "oldest"]
        let ordered = InboundLaneSelectionPolicy.orderedByHeaderMatch(items, rank: { _ in 4 })
        #expect(ordered == items)
    }

    // MARK: - Restore gate

    @Test("restore only when the row bytes changed during the attempt")
    func restoreGate() {
        let before = Data([0x01, 0x02])
        #expect(!InboundLaneSelectionPolicy.shouldRestoreIdentityData(before: before, after: before))
        #expect(InboundLaneSelectionPolicy.shouldRestoreIdentityData(before: before, after: Data([0x01, 0x03])))
        #expect(InboundLaneSelectionPolicy.shouldRestoreIdentityData(before: before, after: Data()))
    }

    // MARK: - Blank adoption

    @Test("a blank opens a lane with a session's first frame, or when there is no lane to split")
    func blankAdoption() {
        #expect(InboundLaneSelectionPolicy.blankMayBecomeLane(receivedMessagesCount: 1, statefulRowExists: true))
        #expect(!InboundLaneSelectionPolicy.blankMayBecomeLane(receivedMessagesCount: 2, statefulRowExists: true),
                "a mid-chain frame belongs to a session this device already holds")
        #expect(InboundLaneSelectionPolicy.blankMayBecomeLane(receivedMessagesCount: 7, statefulRowExists: false),
                "first contact with a lost first frame still bootstraps")
    }

    // MARK: - Negative cache

    @Test("ratchet-state token moves with the receiving side and key material, not with metadata")
    func ratchetStateTokenFields() throws {
        let base = SessionIdentity.UnwrappedProps(
            secretName: "alice",
            deviceId: UUID(),
            sessionContextId: 1,
            longTermPublicKey: Data(repeating: 0x11, count: 32),
            signingPublicKey: Data(repeating: 0x22, count: 32),
            mlKEMPublicKey: try MLKEMPublicKey(id: UUID(), Data(repeating: 0x33, count: 1_568)),
            oneTimePublicKey: nil,
            deviceName: "phone",
            isMasterDevice: false)
        let token = InboundLaneSelectionPolicy.ratchetStateToken(for: base)

        var renamed = base
        renamed.deviceName = PQSSessionConstants.inactiveSessionDeviceNamePrefix + "phone"
        renamed.sessionContextId = 99
        #expect(InboundLaneSelectionPolicy.ratchetStateToken(for: renamed) == token, "archival metadata does not expire a rejection")

        var rekeyed = base
        rekeyed.setLongTermPublicKey(Data(repeating: 0x44, count: 32))
        #expect(InboundLaneSelectionPolicy.ratchetStateToken(for: rekeyed) != token)

        var withOneTimeKey = base
        withOneTimeKey.oneTimePublicKey = try X25519PublicKey(id: UUID(), Data(repeating: 0x55, count: 32))
        #expect(InboundLaneSelectionPolicy.ratchetStateToken(for: withOneTimeKey) != token)
    }

    @Test("same lane, fingerprint and row bytes returns the recorded failure")
    func negativeCacheHit() {
        var cache = InboundNegativeDecryptCache(maxEntries: 8)
        let lane = UUID()
        let fingerprint = Data([0xAA, 0xBB])
        let row = Data(repeating: 0x5A, count: 64)
        cache.recordFailure(laneId: lane, fingerprint: fingerprint, laneState: row, error: TestError(tag: "aead"))
        let hit = cache.cachedFailure(laneId: lane, fingerprint: fingerprint, laneState: row)
        #expect((hit as? TestError) == TestError(tag: "aead"))
        #expect(cache.count == 1)
    }

    @Test("different ciphertext on the same lane is not a hit")
    func negativeCacheMissOnOtherFingerprint() {
        var cache = InboundNegativeDecryptCache(maxEntries: 8)
        let lane = UUID()
        let row = Data(repeating: 0x5A, count: 64)
        cache.recordFailure(laneId: lane, fingerprint: Data([0x01]), laneState: row, error: TestError(tag: "aead"))
        #expect(cache.cachedFailure(laneId: lane, fingerprint: Data([0x02]), laneState: row) == nil)
    }

    @Test("a lane whose ratchet state changed since the failure is retried")
    func negativeCacheExpiresOnStateChange() {
        var cache = InboundNegativeDecryptCache(maxEntries: 8)
        let lane = UUID()
        let fingerprint = Data([0xAA])
        cache.recordFailure(laneId: lane, fingerprint: fingerprint, laneState: Data([0x01]), error: TestError(tag: "aead"))
        #expect(cache.cachedFailure(laneId: lane, fingerprint: fingerprint, laneState: Data([0x02])) == nil)
    }

    @Test("invalidating a lane drops every fingerprint recorded for it and nothing else")
    func negativeCacheInvalidateLane() {
        var cache = InboundNegativeDecryptCache(maxEntries: 8)
        let healed = UUID()
        let other = UUID()
        let row = Data([0x01])
        cache.recordFailure(laneId: healed, fingerprint: Data([0x01]), laneState: row, error: TestError(tag: "a"))
        cache.recordFailure(laneId: healed, fingerprint: Data([0x02]), laneState: row, error: TestError(tag: "b"))
        cache.recordFailure(laneId: other, fingerprint: Data([0x01]), laneState: row, error: TestError(tag: "c"))
        cache.invalidate(laneId: healed)
        #expect(cache.cachedFailure(laneId: healed, fingerprint: Data([0x01]), laneState: row) == nil)
        #expect(cache.cachedFailure(laneId: healed, fingerprint: Data([0x02]), laneState: row) == nil)
        #expect((cache.cachedFailure(laneId: other, fingerprint: Data([0x01]), laneState: row) as? TestError)?.tag == "c")
        #expect(cache.count == 1)
    }

    @Test("cache is bounded and evicts the oldest entry first")
    func negativeCacheBounded() {
        var cache = InboundNegativeDecryptCache(maxEntries: 3)
        let row = Data([0x01])
        let lanes = (0 ..< 4).map { _ in UUID() }
        for (index, lane) in lanes.enumerated() {
            cache.recordFailure(laneId: lane, fingerprint: Data([UInt8(index)]), laneState: row, error: TestError(tag: "\(index)"))
        }
        #expect(cache.count == 3)
        #expect(cache.cachedFailure(laneId: lanes[0], fingerprint: Data([0]), laneState: row) == nil)
        #expect(cache.cachedFailure(laneId: lanes[3], fingerprint: Data([3]), laneState: row) != nil)
    }

    @Test("re-recording an existing key refreshes it instead of growing the cache")
    func negativeCacheRerecordDoesNotGrow() {
        var cache = InboundNegativeDecryptCache(maxEntries: 3)
        let lane = UUID()
        let fingerprint = Data([0x01])
        cache.recordFailure(laneId: lane, fingerprint: fingerprint, laneState: Data([0x01]), error: TestError(tag: "old"))
        cache.recordFailure(laneId: lane, fingerprint: fingerprint, laneState: Data([0x02]), error: TestError(tag: "new"))
        #expect(cache.count == 1)
        #expect((cache.cachedFailure(laneId: lane, fingerprint: fingerprint, laneState: Data([0x02])) as? TestError)?.tag == "new")
        #expect(cache.cachedFailure(laneId: lane, fingerprint: fingerprint, laneState: Data([0x01])) == nil)
    }

    // MARK: - Rollback gate against a real store

    @Test("a failed attempt that left the row unchanged writes nothing to the store")
    func rollbackSkipsStoreWhenRowUnchanged() async throws {
        let session = PQSSession()
        let store = MockIdentityStore(mockUserData: MockUserData(session: session), session: session, isSender: false)
        await session.setDatabaseDelegate(conformer: store)
        let cache = try #require(await session.cache)
        let original = Data(repeating: 0x7E, count: 48)
        let identity = SessionIdentity(id: UUID(), data: original)
        try await cache.createSessionIdentity(identity)
        let pipeline = MessagePipeline()

        let wroteUnchanged = await pipeline.rollBackFailedAttempt(
            identity, dataBeforeAttempt: original, session: session, reason: "test")
        #expect(!wroteUnchanged)
        #expect(await store.updateSessionIdentityCallCount == 0)

        identity.data = Data(repeating: 0x01, count: 48)
        let wroteChanged = await pipeline.rollBackFailedAttempt(
            identity, dataBeforeAttempt: original, session: session, reason: "test")
        #expect(wroteChanged)
        #expect(await store.updateSessionIdentityCallCount == 1)
        #expect(identity.data == original)
        await session.shutdown()
    }

    // MARK: - Stats shape

    @Test("stats derive attempt and skip counts from the attempt list")
    func statsCounts() {
        var stats = InboundLaneSelectionStats(sharedId: "s", pass: .activeFirst, fingerprint: Data())
        let a = UUID(), b = UUID(), c = UUID()
        stats.attempts.append(.init(laneId: a, kind: "preferred", outcome: .failed))
        stats.attempts.append(.init(laneId: b, kind: "active", outcome: .skippedNegativeCache))
        stats.attempts.append(.init(laneId: c, kind: "archived", outcome: .decrypted))
        #expect(stats.decryptAttempts == 2)
        #expect(stats.negativeCacheSkips == 1)
        #expect(stats.attemptedLaneIds == [a, c])
        #expect(stats.skippedLaneIds == [b])
    }
}
