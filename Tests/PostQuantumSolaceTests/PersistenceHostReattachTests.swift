//
//  PersistenceHostReattachTests.swift
//  post-quantum-solace
//
//  Hosts re-attach their store on every password check and app-key read. That
//  must not replace a live `SessionCache`: dropping the warm job and identity
//  lists mid-send produced `preparedCommitFailed error=jobNotFound` storms and
//  lets two caches over one store diverge on ratchet state.
//

import Foundation
@testable import PQSSession
import Testing

@Suite("Persistence host re-attach")
struct PersistenceHostReattachTests {
    @Test("re-attaching the same store keeps the live cache")
    func reattachSameStoreKeepsCache() async throws {
        let session = PQSSession()
        let store = SessionIdentityTests.MockSessionIdentityStore()

        await session.attachPersistenceHost(store)
        let first = await session.persistenceCacheIdentifier
        #expect(first != nil)
        #expect(await session.isPersistenceHostAttached)

        await session.attachPersistenceHost(store)
        #expect(await session.persistenceCacheIdentifier == first)
        await session.shutdown()
    }

    @Test("attaching a different store replaces the cache")
    func attachDifferentStoreReplacesCache() async throws {
        let session = PQSSession()
        await session.attachPersistenceHost(SessionIdentityTests.MockSessionIdentityStore())
        let first = await session.persistenceCacheIdentifier

        await session.attachPersistenceHost(SessionIdentityTests.MockSessionIdentityStore())
        #expect(await session.persistenceCacheIdentifier != first)
        await session.shutdown()
    }

    @Test("a bare session reports no persistence host")
    func bareSessionHasNoHost() async {
        let session = PQSSession()
        #expect(!(await session.isPersistenceHostAttached))
        #expect(await session.persistenceCacheIdentifier == nil)
    }
}
