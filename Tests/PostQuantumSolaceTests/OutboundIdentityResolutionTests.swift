import Foundation
import BinaryCodable
import NeedleTailLogger
import SessionModels
@testable import PQSSession
import Testing

@Suite(.serialized)
actor OutboundIdentityResolutionTests {
    @Test("Outbound send fails before local persistence when no recipient identities can be resolved")
    func outboundTaskWithoutRecipientIdentitiesDoesNotCreateSentLookingMessage() async throws {
        var session = PQSSession()
        let transportStore = TransportStore()
        let transport = _MockTransportDelegate(session: session, store: transportStore)
        let receiver = ReceiverDelegate(session: session)
        let store = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)

        await store.setLocalSalt("offline-no-identity-salt")
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: receiver)
        session.isViable = true
        await transportStore.setPublishableName("alice")

        session = try await session.createSession(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.startSession(appPassword: "123")
        try await receiver.setKey(session.getDatabaseSymmetricKey())

        let cache = try #require(await session.cache)
        let sharedId = "offline-no-identity-shared-id"
        let message = CryptoMessage(
            text: "queued while offline",
            metadata: Data(),
            recipient: .nickname("bob"),
            sentDate: Date(),
            destructionTime: nil)

        do {
            try await session.taskProcessor.outboundTask(
                message: message,
                cache: cache,
                symmetricKey: session.getDatabaseSymmetricKey(),
                session: session,
                sender: "alice",
                type: .nickname("bob"),
                sharedIdOverride: sharedId,
                shouldPersist: true,
                logger: NeedleTailLogger("[ outbound-identity-resolution-test ]"))
            Issue.record("Expected missingSessionIdentity before local message persistence")
        } catch let error as PQSSession.SessionErrors {
            #expect(error == .missingSessionIdentity)
        }

        #expect(try await cache.fetchCachedMessages(sharedId: sharedId).isEmpty)
        #expect(try await cache.fetchJobs().isEmpty)
        #expect(await store.createdMessages.isEmpty)

        await session.shutdown()
    }

    @Test("Non-persistent personal control with no sibling identities is a no-op")
    func nonPersistentPersonalControlWithoutSiblingIdentitiesDoesNotThrowOrCreateJobs() async throws {
        var session = PQSSession()
        let transportStore = TransportStore()
        let transport = _MockTransportDelegate(session: session, store: transportStore)
        let receiver = ReceiverDelegate(session: session)
        let store = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)

        await store.setLocalSalt("offline-personal-control-salt")
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: receiver)
        session.isViable = true
        await transportStore.setPublishableName("alice")

        session = try await session.createSession(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.startSession(appPassword: "123")
        try await receiver.setKey(session.getDatabaseSymmetricKey())

        let cache = try #require(await session.cache)
        let transportInfo = try BinaryEncoder().encode(TransportEvent.refreshOneTimeKeys)
        let message = CryptoMessage(
            text: "",
            metadata: Data(),
            recipient: .personalMessage,
            transportInfo: transportInfo,
            sentDate: Date(),
            destructionTime: nil)

        try await session.taskProcessor.outboundTask(
            message: message,
            cache: cache,
            symmetricKey: session.getDatabaseSymmetricKey(),
            session: session,
            sender: "alice",
            type: .personalMessage,
            sharedIdOverride: "personal-control-no-target-shared-id",
            shouldPersist: false,
            logger: NeedleTailLogger("[ outbound-identity-resolution-test ]"))

        #expect(try await cache.fetchJobs().isEmpty)
        #expect(await store.createdMessages.isEmpty)

        await session.shutdown()
    }

    @Test("Persisted personal message with no sibling identities is stored locally as delivered")
    func persistedPersonalMessageWithoutSiblingIdentitiesPersistsLocallyAsDelivered() async throws {
        var session = PQSSession()
        let transportStore = TransportStore()
        let transport = _MockTransportDelegate(session: session, store: transportStore)
        let receiver = ReceiverDelegate(session: session)
        let store = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: true)

        await store.setLocalSalt("single-device-personal-note-salt")
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: receiver)
        session.isViable = true
        await transportStore.setPublishableName("alice")

        session = try await session.createSession(secretName: "alice", appPassword: "123") {}
        await session.setAppPassword("123")
        session = try await session.startSession(appPassword: "123")
        try await receiver.setKey(session.getDatabaseSymmetricKey())

        let cache = try #require(await session.cache)
        let sharedId = "single-device-personal-note-shared-id"
        let message = CryptoMessage(
            text: "note to self on a single-device account",
            metadata: Data(),
            recipient: .personalMessage,
            sentDate: Date(),
            destructionTime: nil)

        try await session.taskProcessor.outboundTask(
            message: message,
            cache: cache,
            symmetricKey: session.getDatabaseSymmetricKey(),
            session: session,
            sender: "alice",
            type: .personalMessage,
            sharedIdOverride: sharedId,
            shouldPersist: true,
            logger: NeedleTailLogger("[ outbound-identity-resolution-test ]"))

        // No outbound crypto jobs should be scheduled: there is no sibling device.
        #expect(try await cache.fetchJobs().isEmpty)

        let persisted = try await cache.fetchCachedMessages(sharedId: sharedId)
        #expect(persisted.count == 1)
        let savedMessage = try #require(persisted.first)
        let props = try #require(await savedMessage.props(symmetricKey: session.getDatabaseSymmetricKey()))
        #expect(props.deliveryState == .delivered)

        await session.shutdown()
    }
}
