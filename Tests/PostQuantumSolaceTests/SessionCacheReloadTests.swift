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
//
//  Real piece: SessionCache. Double: the store, which runs a cache call after a read has taken
//  its rows (or at the start of a write), the turn a real store's await gives.
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
