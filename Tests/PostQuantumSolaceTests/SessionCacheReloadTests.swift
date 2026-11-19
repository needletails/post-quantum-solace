//
//  SessionCacheReloadTests.swift
//  post-quantum-solace
//
//  SessionCache replaces whole in-memory lists with a store read: refreshCache, the
//  fetch-on-empty reads, the updateSessionIdentity and commitPreparedOutbound preloads, and the
//  job merge in jobIndex(for:). The store answers after an await, so a cache write can finish
//  while the read is in flight. When the read's rows were taken before that write, assigning
//  them put older data back: an identity's earlier ratchet bytes, a created job gone, a deleted
//  job back. Writers that changed memory before the store (contacts, communications, media
//  jobs) lost their change the same way when a reload ran during their store write.
//  Reproduced against the app's SQLiteStore with no forcing (scratch harness
//  RealStoreCacheReloadRaceTests); these tests take the same order deterministically.
//  A reload must also finish after one read however often writers publish, and a create whose
//  row a reload already read must not leave the row in memory twice.
//
//  Real piece: SessionCache. Double: the store, which runs a cache call after a read has taken
//  its rows (or at the start of a write, or after a create has stored its row), the turn a real
//  store's await gives.
//

import DoubleRatchetKit
import Foundation
@testable import PQSSession
import SessionModels
import Testing
import Crypto

@Suite(.serialized)
struct SessionCacheReloadTests {
    typealias Store = SessionIdentityTests.MockSessionIdentityStore

    private let key = SymmetricKey(size: .bits256)

    private func identity(_ byte: UInt8, id: UUID = UUID()) -> SessionIdentity {
        SessionIdentity(id: id, data: Data([byte]))
    }

    private func job() throws -> JobModel {
        try JobModel(
            id: UUID(),
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
                attempts: 0),
            symmetricKey: key)
    }

    private func memoryData(_ cache: SessionCache, _ id: UUID) async throws -> Data? {
        try await cache.fetchSessionIdentities().first { $0.id == id }?.data
    }

    private func storeData(_ store: Store, _ id: UUID) -> Data? {
        store.identities.first { $0.id == id }?.data
    }

    // MARK: - Reloads and writers that persist first

    @Test("refreshCache keeps an identity update that finished during its read")
    func refreshKeepsIdentityUpdate() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1)
        try await cache.createSessionIdentity(a)
        let a2 = identity(0xA2, id: a.id)
        store.afterNextRead[.identities] = { try await cache.updateSessionIdentity(a2) }

        try await cache.refreshCache()

        #expect(storeData(store, a.id) == Data([0xA2]))
        #expect(try await memoryData(cache, a.id) == Data([0xA2]), "memory went back to the earlier bytes")
    }

    @Test("refreshCache keeps a job created during its read")
    func refreshKeepsCreatedJob() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        try await cache.createJob(try job())
        let created = try job()
        store.afterNextRead[.jobs] = { try await cache.createJob(created) }

        try await cache.refreshCache()

        #expect(store.jobs.contains { $0.id == created.id })
        #expect(await cache.isCached(created), "the created job is gone from memory")
    }

    @Test("refreshCache does not bring back a job deleted during its read")
    func refreshDoesNotBringBackDeletedJob() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let kept = try job(), doomed = try job()
        try await cache.createJob(kept)
        try await cache.createJob(doomed)
        store.afterNextRead[.jobs] = { try await cache.deleteJob(doomed) }

        try await cache.refreshCache()

        #expect(!store.jobs.contains { $0.id == doomed.id })
        #expect(!(await cache.isCached(doomed)), "the deleted job is back in memory")
        #expect(await cache.isCached(kept))
    }

    @Test("refreshCache keeps a contact, communication and media job created during their reads")
    func refreshKeepsCreatedContactCommunicationAndMediaJob() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        // One row each already, so the checks below read memory rather than reloading.
        try await cache.createContact(ContactModel(id: UUID(), data: Data([0])))
        try await cache.createCommunication(BaseCommunication(id: UUID(), data: Data([0])))
        try await cache.createMediaJob(DataPacket(id: UUID(), data: Data([0])))
        let contact = ContactModel(id: UUID(), data: Data([1]))
        let communication = BaseCommunication(id: UUID(), data: Data([2]))
        let packet = DataPacket(id: UUID(), data: Data([3]))
        store.afterNextRead[.contacts] = { try await cache.createContact(contact) }
        store.afterNextRead[.communications] = { try await cache.createCommunication(communication) }
        store.afterNextRead[.mediaJobs] = { try await cache.createMediaJob(packet) }

        try await cache.refreshCache()

        #expect(await cache.isCached(contact), "contact")
        #expect(try await cache.fetchCommunications().contains { $0.id == communication.id }, "communication")
        #expect(await cache.isCached(packet), "media job")
    }

    @Test("A cold fetchSessionIdentities keeps an identity update that finished during its read")
    func coldIdentityFetchKeepsUpdate() async throws {
        let store = Store()
        let a = identity(0xA1)
        store.identities = [a] // on disk; this cache's lists are empty (re-attached store)
        let cache = SessionCache(store: store)
        let a2 = identity(0xA2, id: a.id)
        store.afterNextRead[.identities] = { try await cache.updateSessionIdentity(a2) }

        _ = try await cache.fetchSessionIdentities()

        #expect(storeData(store, a.id) == Data([0xA2]))
        #expect(try await memoryData(cache, a.id) == Data([0xA2]), "memory went back to the earlier bytes")
    }

    @Test("updateSessionIdentity's cold preload keeps an identity created during its read")
    func coldUpdatePreloadKeepsCreatedIdentity() async throws {
        let store = Store()
        let a = identity(0xA1), b = identity(0xB1)
        store.identities = [a]
        let cache = SessionCache(store: store)
        store.afterNextRead[.identities] = { try await cache.createSessionIdentity(b) }

        try await cache.updateSessionIdentity(identity(0xA2, id: a.id))

        #expect(storeData(store, b.id) == Data([0xB1]))
        #expect(try await memoryData(cache, b.id) == Data([0xB1]), "the created identity is gone from memory")
        #expect(try await memoryData(cache, a.id) == Data([0xA2]))
    }

    @Test("Cold fetches of contacts, communications, jobs and media jobs keep rows created during their reads")
    func coldFetchesKeepCreatedRows() async throws {
        let store = Store()
        store.contacts = [ContactModel(id: UUID(), data: Data([1]))]
        store.communications = [BaseCommunication(id: UUID(), data: Data([2]))]
        store.jobs = [try job()]
        store.mediaJobs = [DataPacket(id: UUID(), data: Data([3]))]
        let cache = SessionCache(store: store)
        let contact = ContactModel(id: UUID(), data: Data([4]))
        let communication = BaseCommunication(id: UUID(), data: Data([5]))
        let created = try job()
        let packet = DataPacket(id: UUID(), data: Data([6]))
        store.afterNextRead[.contacts] = { try await cache.createContact(contact) }
        store.afterNextRead[.communications] = { try await cache.createCommunication(communication) }
        store.afterNextRead[.jobs] = { try await cache.createJob(created) }
        store.afterNextRead[.mediaJobs] = { try await cache.createMediaJob(packet) }

        _ = try await cache.fetchContacts()
        _ = try await cache.fetchCommunications()
        _ = try await cache.fetchJobs()
        _ = try await cache.fetchAllMediaJobs()

        #expect(await cache.isCached(contact), "contact")
        #expect(try await cache.fetchCommunications().contains { $0.id == communication.id }, "communication")
        #expect(await cache.isCached(created), "job")
        #expect(await cache.isCached(packet), "media job")
        // The rows already on disk are loaded too.
        #expect(try await cache.fetchContacts().count == 2)
        #expect(try await cache.fetchCommunications().count == 2)
        #expect(try await cache.fetchJobs().count == 2)
        #expect(try await cache.fetchAllMediaJobs().count == 2)
    }

    @Test("commitPreparedOutbound's preload keeps an identity update that finished during its read")
    func commitPreloadKeepsIdentityUpdate() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1)
        try await cache.createSessionIdentity(a)
        let external = identity(0xE1)
        store.identities.append(external) // another process's lane: on disk, not in memory
        let prepared = try job()
        try await cache.createJob(prepared)
        let a2 = identity(0xA2, id: a.id)
        store.afterNextRead[.identities] = { try await cache.updateSessionIdentity(a2) }

        try await cache.commitPreparedOutbound(sessionIdentity: identity(0xE2, id: external.id), job: prepared)

        #expect(storeData(store, a.id) == Data([0xA2]))
        #expect(try await memoryData(cache, a.id) == Data([0xA2]), "memory went back to the earlier bytes")
        #expect(try await memoryData(cache, external.id) == Data([0xE2]))
    }

    @Test("updateJob's store merge does not bring back a job deleted during its read")
    func jobMergeDoesNotBringBackDeletedJob() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let doomed = try job()
        try await cache.createJob(doomed)
        let external = try job()
        store.jobs.append(external) // on disk, not in memory
        store.afterNextRead[.jobs] = { try await cache.deleteJob(doomed) }

        try await cache.updateJob(external)

        #expect(!store.jobs.contains { $0.id == doomed.id })
        #expect(!(await cache.isCached(doomed)), "the deleted job is back in memory")
        #expect(await cache.isCached(external))
    }

    // MARK: - Writers that changed memory before the store

    @Test("A contact update keeps its change when a reload runs during its store write")
    func contactUpdateSurvivesReloadDuringWrite() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let id = UUID()
        try await cache.createContact(ContactModel(id: id, data: Data([1])))
        store.beforeNextWrite = { try await cache.refreshCache() }

        try await cache.updateContact(ContactModel(id: id, data: Data([2])))

        #expect(store.contacts.first { $0.id == id }?.data == Data([2]))
        #expect(try await cache.fetchContacts().first { $0.id == id }?.data == Data([2]), "memory went back to the earlier contact")
    }

    @Test("A deleted contact stays deleted when a reload runs during its store write")
    func contactDeleteSurvivesReloadDuringWrite() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let kept = ContactModel(id: UUID(), data: Data([1])), doomed = ContactModel(id: UUID(), data: Data([2]))
        try await cache.createContact(kept)
        try await cache.createContact(doomed)
        store.beforeNextWrite = { try await cache.refreshCache() }

        try await cache.deleteContact(doomed.id)

        #expect(!store.contacts.contains { $0.id == doomed.id })
        #expect(!(await cache.isCached(doomed)), "the deleted contact is back in memory")
    }

    @Test("A communication update keeps its change when a reload runs during its store write")
    func communicationUpdateSurvivesReloadDuringWrite() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let id = UUID()
        try await cache.createCommunication(BaseCommunication(id: id, data: Data([1])))
        store.beforeNextWrite = { try await cache.refreshCache() }

        try await cache.updateCommunication(BaseCommunication(id: id, data: Data([2])))

        #expect(store.communications.first { $0.id == id }?.data == Data([2]))
        #expect(try await cache.fetchCommunications().first { $0.id == id }?.data == Data([2]), "memory went back to the earlier communication")
    }

    @Test("A deleted communication stays deleted when a reload runs during its store write")
    func communicationDeleteSurvivesReloadDuringWrite() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let kept = BaseCommunication(id: UUID(), data: Data([1])), doomed = BaseCommunication(id: UUID(), data: Data([2]))
        try await cache.createCommunication(kept)
        try await cache.createCommunication(doomed)
        store.beforeNextWrite = { try await cache.refreshCache() }

        try await cache.deleteCommunication(doomed)

        #expect(!store.communications.contains { $0.id == doomed.id })
        #expect(!(try await cache.fetchCommunications().contains { $0.id == doomed.id }), "the deleted communication is back in memory")
    }

    @Test("A deleted media job stays deleted when a reload runs during its store write")
    func mediaJobDeleteSurvivesReloadDuringWrite() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let kept = DataPacket(id: UUID(), data: Data([1])), doomed = DataPacket(id: UUID(), data: Data([2]))
        try await cache.createMediaJob(kept)
        try await cache.createMediaJob(doomed)
        store.beforeNextWrite = { try await cache.refreshCache() }

        try await cache.deleteMediaJob(doomed.id)

        #expect(!store.mediaJobs.contains { $0.id == doomed.id })
        #expect(!(await cache.isCached(doomed)), "the deleted media job is back in memory")
    }

    // MARK: - One read per reload, one copy per row

    @Test("refreshCache reads each list once while cache writes land during every read, and memory ends equal to the store")
    func refreshReadsOnceWhileWritesLand() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0)
        try await cache.createSessionIdentity(a)
        try await cache.createJob(try job())
        let contactId = UUID()
        try await cache.createContact(ContactModel(id: contactId, data: Data([0])))
        try await cache.createCommunication(BaseCommunication(id: UUID(), data: Data([0])))
        try await cache.createMediaJob(DataPacket(id: UUID(), data: Data([0])))
        let created = try (0..<50).map { _ in try job() }
        // Another task's writes publish during every read, to the list being read and to the
        // others. Bounded at 50 reads, so a reload that reads until none landed still ends.
        store.afterEachRead = { _ in
            let n = store.reads.values.reduce(0, +)
            guard n <= created.count else { return }
            try await cache.updateSessionIdentity(SessionIdentity(id: a.id, data: Data([UInt8(n)])))
            try await cache.createJob(created[n - 1])
            try await cache.updateContact(ContactModel(id: contactId, data: Data([UInt8(n)])))
        }

        try await cache.refreshCache()
        store.afterEachRead = nil

        #expect(store.reads == [.identities: 1, .contacts: 1, .communications: 1, .jobs: 1, .mediaJobs: 1],
                "a reload read a list more than once")
        #expect(try await cache.fetchSessionIdentities().map(\.data) == store.identities.map(\.data), "identity")
        #expect(Set(try await cache.fetchJobs().map(\.id)) == Set(store.jobs.map(\.id)), "jobs")
        #expect(try await cache.fetchJobs().count == store.jobs.count, "a job held twice")
        #expect(try await cache.fetchContacts().map(\.data) == store.contacts.map(\.data), "contact")
    }

    @Test("An identity created while a reload reads the store is held once, and its next update reaches it")
    func identityCreatedUnderReloadIsHeldOnce() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        try await cache.createSessionIdentity(identity(0x01))
        let b = identity(0xB1)
        // The reload reads after the create's store write and before the create publishes.
        store.afterNextCreate = { try await cache.refreshCache() }

        try await cache.createSessionIdentity(b)
        try await cache.updateSessionIdentity(identity(0xB2, id: b.id))

        #expect(try await cache.fetchSessionIdentities().filter { $0.id == b.id }.map(\.data) == [Data([0xB2])],
                "a second copy kept the earlier bytes")
    }

    @Test("A job, contact, communication and media job created while a cold fetch reads the store are each held once")
    func rowsCreatedUnderColdFetchAreHeldOnce() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let created = try job()
        let contact = ContactModel(id: UUID(), data: Data([1]))
        let communication = BaseCommunication(id: UUID(), data: Data([2]))
        let packet = DataPacket(id: UUID(), data: Data([3]))
        // Each list is empty, so each fetch reads the store; it runs after the create's store
        // write and before the create publishes.
        store.afterNextCreate = { _ = try await cache.fetchJobs() }
        try await cache.createJob(created)
        store.afterNextCreate = { _ = try await cache.fetchContacts() }
        try await cache.createContact(contact)
        store.afterNextCreate = { _ = try await cache.fetchCommunications() }
        try await cache.createCommunication(communication)
        store.afterNextCreate = { _ = try await cache.fetchAllMediaJobs() }
        try await cache.createMediaJob(packet)

        #expect(try await cache.fetchJobs().filter { $0.id == created.id }.count == 1, "job")
        #expect(try await cache.fetchContacts().filter { $0.id == contact.id }.count == 1, "contact")
        #expect(try await cache.fetchCommunications().filter { $0.id == communication.id }.count == 1, "communication")
        #expect(try await cache.fetchAllMediaJobs().filter { $0.id == packet.id }.count == 1, "media job")
    }

    @Test("A reload that read before another process's write does not undo a later reload that loaded it")
    func olderReloadDoesNotUndoNewerReload() async throws {
        let store = Store()
        let a = identity(0xA1)
        store.identities = [a]
        let cache = SessionCache(store: store) // cold: the fetch below reads the store
        let advanced = identity(0xA9, id: a.id)
        store.afterNextRead[.identities] = {
            // While that read is in flight, another process advances the lane and the host
            // refreshes the cache.
            store.identities = [advanced]
            try await cache.refreshCache()
        }

        _ = try await cache.fetchSessionIdentities()

        #expect(try await memoryData(cache, a.id) == Data([0xA9]), "memory went back to the bytes from before the other process's write")
    }

    @Test("A reload that began before clearCache leaves memory empty, so the next fetch reads the store")
    func reloadAcrossClearCacheLeavesMemoryEmpty() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1), b = identity(0xB1)
        try await cache.createSessionIdentity(a)
        try await cache.createSessionIdentity(b)
        let a2 = identity(0xA2, id: a.id)
        store.afterNextRead[.identities] = {
            try await cache.updateSessionIdentity(a2)
            await cache.clearCache()
        }

        try await cache.refreshCache()

        #expect(try await memoryData(cache, a.id) == Data([0xA2]), "memory went back to the earlier bytes or lost the row")
        #expect(try await memoryData(cache, b.id) == Data([0xB1]))
    }

    @Test("fetchMediaJob(id:) does not put back a media job deleted during its read")
    func singleMediaJobReadDoesNotBringBackDeletedJob() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        try await cache.createMediaJob(DataPacket(id: UUID(), data: Data([1])))
        let doomed = DataPacket(id: UUID(), data: Data([2]))
        store.mediaJobs.append(doomed) // on disk, not in memory
        store.afterNextRead[.mediaJobs] = { try await cache.deleteMediaJob(doomed.id) }

        _ = try await cache.fetchMediaJob(id: doomed.id)

        #expect(!store.mediaJobs.contains { $0.id == doomed.id })
        #expect(!(await cache.isCached(doomed)), "the deleted media job is back in memory")
    }

    @Test("fetchMediaJob(id:) on a cold cache leaves fetchAllMediaJobs reading the store")
    func coldSingleMediaJobReadKeepsTheListWhole() async throws {
        let store = Store()
        let first = DataPacket(id: UUID(), data: Data([1])), second = DataPacket(id: UUID(), data: Data([2]))
        store.mediaJobs = [first, second]
        let cache = SessionCache(store: store)

        #expect(try await cache.fetchMediaJob(id: first.id)?.id == first.id)
        #expect(try await cache.fetchAllMediaJobs().map(\.id) == [first.id, second.id], "the list held only the row read by id")
    }

    // MARK: - Controls

    @Test("Control: refreshCache loads what another process wrote, with a cache read during the read")
    func refreshLoadsExternalWrites() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let a = identity(0xA1)
        try await cache.createSessionIdentity(a)
        let gone = try job()
        try await cache.createJob(gone)
        let contactId = UUID(), communicationId = UUID()
        try await cache.createContact(ContactModel(id: contactId, data: Data([1])))
        try await cache.createCommunication(BaseCommunication(id: communicationId, data: Data([1])))
        // Another process writes the store directly.
        store.identities = [identity(0xA9, id: a.id), identity(0xB9)]
        let added = try job()
        store.jobs = [added]
        store.contacts = [ContactModel(id: contactId, data: Data([9]))]
        store.communications = [BaseCommunication(id: communicationId, data: Data([9]))]
        let packet = DataPacket(id: UUID(), data: Data([9]))
        store.mediaJobs = [packet]
        // A read-only cache call during each read changes nothing.
        store.afterNextRead[.identities] = { _ = await cache.getCacheStats() }
        store.afterNextRead[.jobs] = { _ = await cache.isCached(added) }

        try await cache.refreshCache()

        #expect(try await cache.fetchSessionIdentities().map(\.data) == [Data([0xA9]), Data([0xB9])])
        #expect(await cache.isCached(added))
        #expect(!(await cache.isCached(gone)))
        #expect(try await cache.fetchContacts().map(\.data) == [Data([9])])
        #expect(try await cache.fetchCommunications().map(\.data) == [Data([9])])
        #expect(try await cache.fetchAllMediaJobs().map(\.id) == [packet.id])
    }

    @Test("Control: writers with no reload running publish their change")
    func writersWithoutReload() async throws {
        let store = Store()
        let cache = SessionCache(store: store)
        let contactId = UUID(), communicationId = UUID()
        try await cache.createContact(ContactModel(id: contactId, data: Data([1])))
        try await cache.createCommunication(BaseCommunication(id: communicationId, data: Data([1])))
        let packet = DataPacket(id: UUID(), data: Data([1]))
        try await cache.createMediaJob(packet)
        store.beforeNextWrite = {}

        try await cache.updateContact(ContactModel(id: contactId, data: Data([2])))
        try await cache.updateCommunication(BaseCommunication(id: communicationId, data: Data([2])))
        try await cache.deleteMediaJob(packet.id)

        #expect(try await cache.fetchContacts().map(\.data) == [Data([2])])
        #expect(try await cache.fetchCommunications().map(\.data) == [Data([2])])
        #expect(!(await cache.isCached(packet)))
        #expect(store.contacts.map(\.data) == [Data([2])])
        #expect(store.communications.map(\.data) == [Data([2])])
        #expect(store.mediaJobs.isEmpty)
    }
}
