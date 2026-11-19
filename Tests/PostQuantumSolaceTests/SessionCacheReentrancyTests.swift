//
//  SessionCacheReentrancyTests.swift
//  post-quantum-solace
//
//  SessionCache is an actor: while one call waits on the store, others run. An update that
//  found its row's position in the in-memory list before the store write, and wrote through
//  that position after it, wrote to the wrong slot when another call deleted an earlier row
//  in between: it replaced the next row, or ran past the end of the list and stopped the
//  process. Seen in compromiseRotationWithCrossingTraffic, where an inbound lane rollback
//  deleted a session identity while the host accepted a peer's new one.
//
//  Real piece: SessionCache. Double: the store, which lets the test run a cache call after
//  the store write and before the update resumes, the turn a real store's await gives.
//

import DoubleRatchetKit
import Foundation
@testable import PQSSession
import SessionModels
import Testing
import Crypto

@Suite(.serialized)
struct SessionCacheReentrancyTests {
    typealias Store = SessionIdentityTests.MockSessionIdentityStore

    private func identity(_ byte: UInt8) -> SessionIdentity {
        SessionIdentity(id: UUID(), data: Data([byte]))
    }

    private func job(id: UUID = UUID(), attempts: Int, key: SymmetricKey) throws -> JobModel {
        try JobModel(
            id: id,
            props: .init(
                sequenceId: 1,
                task: .init(task: .writeMessage(.init(
                    message: CryptoMessage(
                        text: "job",
                        metadata: .init(),
                        recipient: .nickname("bob"),
                        sentDate: Date(),
                        destructionTime: nil),
                    recipientIdentity: identity(0),
                    localId: UUID(),
                    sharedId: UUID().uuidString,
                    isPersistedOutbound: false))),
                isBackgroundTask: true,
                scheduledAt: Date(),
                attempts: attempts),
            symmetricKey: key)
    }

    /// Identities in the cache as (id, data), in list order.
    private func identities(_ cache: SessionCache) async throws -> [(UUID, Data)] {
        try await cache.fetchSessionIdentities().map { ($0.id, $0.data) }
    }

    /// Jobs in the cache as (id, attempts), in list order.
    private func jobs(_ cache: SessionCache, key: SymmetricKey) async throws -> [(UUID, Int?)] {
        var result: [(UUID, Int?)] = []
        for job in try await cache.fetchJobs() {
            result.append((job.id, await job.props(symmetricKey: key)?.attempts))
        }
        return result
    }

    // MARK: - Session identities

    @Test("An identity update keeps the next row when an earlier one is deleted during the write")
    func identityUpdateKeepsTheNextRow() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1), b = identity(0xB1), c = identity(0xC1)
        for row in [a, b, c] { try await cache.createSessionIdentity(row) }
        store.afterNextUpdate = { try await cache.deleteSessionIdentity(a.id) }

        try await cache.updateSessionIdentity(SessionIdentity(id: b.id, data: Data([0xB2])))

        let rows = try await identities(cache)
        #expect(rows.map(\.0) == [b.id, c.id], "rows: \(rows.map(\.0))")
        #expect(rows.first { $0.0 == b.id }?.1 == Data([0xB2]))
        #expect(rows.first { $0.0 == c.id }?.1 == Data([0xC1]))
    }

    @Test("An identity update of the last row survives an earlier row being deleted during the write")
    func identityUpdateOfTheLastRowDoesNotRunPastTheEnd() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1), b = identity(0xB1)
        for row in [a, b] { try await cache.createSessionIdentity(row) }
        store.afterNextUpdate = { try await cache.deleteSessionIdentity(a.id) }

        try await cache.updateSessionIdentity(SessionIdentity(id: b.id, data: Data([0xB2])))

        let rows = try await identities(cache)
        #expect(rows.map(\.0) == [b.id])
        #expect(rows.first?.1 == Data([0xB2]))
    }

    @Test("An identity deleted while its update is written stays deleted")
    func identityDeletedDuringItsUpdateStaysDeleted() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1), b = identity(0xB1), c = identity(0xC1)
        for row in [a, b, c] { try await cache.createSessionIdentity(row) }
        store.afterNextUpdate = { try await cache.deleteSessionIdentity(b.id) }

        try await cache.updateSessionIdentity(SessionIdentity(id: b.id, data: Data([0xB2])))

        let rows = try await identities(cache)
        #expect(rows.map(\.0) == [a.id, c.id], "rows: \(rows.map(\.0))")
        #expect(rows.first { $0.0 == c.id }?.1 == Data([0xC1]))
        #expect(!store.identities.contains { $0.id == b.id })
    }

    @Test("Control: an identity update with nothing else running replaces only its row")
    func identityUpdateWithNothingElseRunning() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1), b = identity(0xB1), c = identity(0xC1)
        for row in [a, b, c] { try await cache.createSessionIdentity(row) }
        store.afterNextUpdate = {}

        try await cache.updateSessionIdentity(SessionIdentity(id: b.id, data: Data([0xB2])))

        let rows = try await identities(cache)
        #expect(rows.map(\.0) == [a.id, b.id, c.id])
        #expect(rows.map(\.1) == [Data([0xA1]), Data([0xB2]), Data([0xC1])])
    }

    // MARK: - Jobs

    @Test("A job update keeps the next job when an earlier one is deleted during the write")
    func jobUpdateKeepsTheNextJob() async throws {
        let key = SymmetricKey(size: .bits256)
        let store = Store()
        let cache = SessionCache(store: store)
        let j1 = try job(attempts: 0, key: key), j2 = try job(attempts: 0, key: key), j3 = try job(attempts: 0, key: key)
        for row in [j1, j2, j3] { try await cache.createJob(row) }
        store.afterNextUpdate = { try await cache.deleteJob(j1) }

        try await cache.updateJob(try job(id: j2.id, attempts: 1, key: key))

        let rows = try await jobs(cache, key: key)
        #expect(rows.map(\.0) == [j2.id, j3.id], "jobs: \(rows.map(\.0))")
        #expect(rows.first { $0.0 == j2.id }?.1 == 1)
        #expect(rows.first { $0.0 == j3.id }?.1 == 0)
    }

    @Test("A job update of the last job survives an earlier job being deleted during the write")
    func jobUpdateOfTheLastJobDoesNotRunPastTheEnd() async throws {
        let key = SymmetricKey(size: .bits256)
        let store = Store()
        let cache = SessionCache(store: store)
        let j1 = try job(attempts: 0, key: key), j2 = try job(attempts: 0, key: key)
        for row in [j1, j2] { try await cache.createJob(row) }
        store.afterNextUpdate = { try await cache.deleteJob(j1) }

        try await cache.updateJob(try job(id: j2.id, attempts: 1, key: key))

        let rows = try await jobs(cache, key: key)
        #expect(rows.map(\.0) == [j2.id])
        #expect(rows.first?.1 == 1)
    }

    // MARK: - Prepared outbound commit

    @Test("A prepared-outbound commit keeps the next identity and job when earlier ones are deleted during the write")
    func preparedOutboundCommitKeepsTheNextRows() async throws {
        let key = SymmetricKey(size: .bits256)
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1), b = identity(0xB1), c = identity(0xC1)
        for row in [a, b, c] { try await cache.createSessionIdentity(row) }
        let j1 = try job(attempts: 0, key: key), j2 = try job(attempts: 0, key: key), j3 = try job(attempts: 0, key: key)
        for row in [j1, j2, j3] { try await cache.createJob(row) }
        store.afterNextUpdate = {
            try await cache.deleteSessionIdentity(a.id)
            try await cache.deleteJob(j1)
        }

        try await cache.commitPreparedOutbound(
            sessionIdentity: SessionIdentity(id: b.id, data: Data([0xB2])),
            job: try job(id: j2.id, attempts: 1, key: key))

        let identityRows = try await identities(cache)
        #expect(identityRows.map(\.0) == [b.id, c.id], "identities: \(identityRows.map(\.0))")
        #expect(identityRows.first { $0.0 == b.id }?.1 == Data([0xB2]))
        #expect(identityRows.first { $0.0 == c.id }?.1 == Data([0xC1]))
        let jobRows = try await jobs(cache, key: key)
        #expect(jobRows.map(\.0) == [j2.id, j3.id], "jobs: \(jobRows.map(\.0))")
        #expect(jobRows.first { $0.0 == j2.id }?.1 == 1)
        #expect(jobRows.first { $0.0 == j3.id }?.1 == 0)
    }
}
