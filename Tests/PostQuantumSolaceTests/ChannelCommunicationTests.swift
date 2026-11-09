//
//  ChannelCommunicationTests.swift
//  post-quantum-solace
//
//  Created by AI Assistant on 2025-12-07.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing

@Suite(.serialized)
actor ChannelCommunicationTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    private func setupSession() async throws -> (SessionCache, SymmetricKey) {
        let mockUserData = MockUserData(session: session)
        let backingStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await backingStore.setLocalSalt("channelSalt")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: backingStore)
        await session.setTransportDelegate(conformer: transport)
        await session.setPQSSessionDelegate(conformer: SessionDelegate(session: session))
        await session.setReceiverDelegate(conformer: ReceiverDelegate(session: session))

        await session.setConnectivity(true)
        await store.setPublishableName(mockUserData.ssn)

        session = try await session.createAccount(
            secretName: mockUserData.ssn,
            appPassword: mockUserData.sap
        ) {}

        await session.setAppPassword(mockUserData.sap)
        session = try await session.unlock(appPassword: mockUserData.sap)

        guard let cache = await session.cache else {
            Issue.record("Session cache should be initialized")
            throw PQSError.databaseNotInitialized
        }

        let symmetricKey = try await session.getDatabaseSymmetricKey()
        return (cache, symmetricKey)
    }

    // MARK: - Tests

    @Test("createChannelCommunication should throw when member count is invalid")
    func testCreateChannelCommunication_invalidMemberCount() async throws {
        let (cache, symmetricKey) = try await setupSession()

        await #expect(throws: PQSError.invalidMemberCount.self) {
            try await session.messagePipeline.createChannelCommunication(
                sender: "alice",
                recipient: .channel("general"),
                channelName: "general",
                administrator: "alice",
                members: ["alice"], // invalid: too few members
                operators: ["alice"],
                symmetricKey: symmetricKey,
                session: session,
                cache: cache,
                metadata: Data()
            )
        }

        await session.shutdown()
    }

    @Test("createChannelCommunication should not synchronize when shouldSynchronize is false")
    func testCreateChannelCommunication_noSynchronizationWhenDisabled() async throws {
        let (cache, symmetricKey) = try await setupSession()

        // Record current count instead of assuming empty cache
        let initialCommunications = try await cache.fetchCommunications()
        let initialCount = initialCommunications.count

        try await session.messagePipeline.createChannelCommunication(
            sender: "alice",
            recipient: .channel("general"),
            channelName: "general",
            administrator: "alice",
            members: ["alice", "bob", "joe"],
            operators: ["alice"],
            symmetricKey: symmetricKey,
            session: session,
            cache: cache,
            metadata: Data(),
            shouldSynchronize: false
        )

        // Communication should be created locally
        let communications = try await cache.fetchCommunications()
        #expect(communications.count == initialCount + 1)

        await session.shutdown()
    }

    @Test("updateChannelMembership expands persisted channel roster")
    func testUpdateChannelMembership_expandsRoster() async throws {
        let (cache, symmetricKey) = try await setupSession()

        let metadata = try BinaryEncoder().encode(
            ChannelStoredMetadata(
                core: ChannelInfo(
                    name: "general",
                    administrator: "alice",
                    members: ["alice", "bob"],
                    operators: ["alice"]),
                overlay: ChannelLocalOverlay(
                    userMarkedPinned: true,
                    displayTitle: "General team")))

        try await session.messagePipeline.createChannelCommunication(
            sender: "alice",
            recipient: .channel("general"),
            channelName: "general",
            administrator: "alice",
            members: ["alice", "bob"],
            operators: ["alice"],
            symmetricKey: symmetricKey,
            session: session,
            cache: cache,
            metadata: metadata,
            shouldSynchronize: false)

        try await session.messagePipeline.updateChannelMembership(
            channelName: "general",
            administrator: "alice",
            members: ["alice", "bob", "carol"],
            operators: ["alice"],
            symmetricKey: symmetricKey,
            session: session,
            cache: cache,
            shouldSynchronize: false)

        let communication = try await session.messagePipeline.conversation(
            cache: cache,
            communicationType: .channel("general"),
            session: session)
        let props = await communication.props(symmetricKey: symmetricKey)
        #expect(props?.members.contains("carol") == true)
        #expect(props?.members.count == 3)

        let decoded = try BinaryDecoder().decode(ChannelStoredMetadata.self, from: props!.metadata)
        #expect(decoded.core.members.contains("carol"))
        #expect(decoded.overlay?.userMarkedPinned == true)
        #expect(decoded.overlay?.displayTitle == "General team")

        await session.shutdown()
    }

    /// The channel picture is stored on every roster update but sent only when it changes:
    /// a synchronization is one encrypted copy per member device, so a roster-only update
    /// must not carry it.
    @Test("updateChannelMembership stores the channel image and sends it only when it changes")
    func testUpdateChannelMembership_imageStoredAndSentOnlyOnChange() async throws {
        let (cache, symmetricKey) = try await setupSession()
        let delegate = SynchronizationCapturingDelegate()
        await session.setPQSSessionDelegate(conformer: delegate)
        let picture = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02, 0x03])

        try await session.messagePipeline.createChannelCommunication(
            sender: "alice",
            recipient: .channel("general"),
            channelName: "general",
            administrator: "alice",
            members: ["alice", "bob"],
            operators: ["alice"],
            symmetricKey: symmetricKey,
            session: session,
            cache: cache,
            metadata: try BinaryEncoder().encode(
                ChannelInfo(
                    name: "general",
                    administrator: "alice",
                    members: ["alice", "bob"],
                    operators: ["alice"],
                    title: "General")),
            shouldSynchronize: false)

        func update(members: Set<String>, image: Data?, imageVersion: UInt64? = nil) async throws {
            try await session.messagePipeline.updateChannelMembership(
                channelName: "general",
                administrator: "alice",
                members: members,
                operators: ["alice"],
                image: image,
                imageVersion: imageVersion,
                symmetricKey: symmetricKey,
                session: session,
                cache: cache,
                shouldSynchronize: true)
        }
        func stored() async throws -> ChannelInfo {
            let communication = try await session.messagePipeline.conversation(
                cache: cache,
                communicationType: .channel("general"),
                session: session)
            let props = try #require(await communication.props(symmetricKey: symmetricKey))
            return try BinaryDecoder().decode(ChannelStoredMetadata.self, from: props.metadata).core
        }
        func lastSent() async throws -> ChannelInfo {
            try BinaryDecoder().decode(ChannelInfo.self, from: try #require(await delegate.channelMetadata.last))
        }

        // Setting the image stores it and sends it.
        try await update(members: ["alice", "bob"], image: picture)
        #expect(try await stored().image == picture)
        #expect(try await stored().imageVersion == 1)
        #expect(try await lastSent().image == picture)
        #expect(try await lastSent().imageVersion == 1)

        // A roster change keeps it stored, and keeps it off the wire.
        try await update(members: ["alice", "bob", "carol"], image: nil)
        #expect(try await stored().image == picture)
        #expect(try await stored().title == "General")
        #expect(try await stored().members.contains("carol"))
        #expect(try await lastSent().image == nil)
        #expect(try await lastSent().imageDigest == ChannelInfo.imageDigest(of: picture))
        #expect(try await stored().imageDigest == nil)
        #expect(try await stored().imageVersion == 1)
        #expect(try await lastSent().imageVersion == 1)
        #expect(try await lastSent().members.contains("carol"))

        // Empty data removes it here and tells the members to remove it.
        try await update(members: ["alice", "bob", "carol"], image: Data())
        #expect(try await stored().image == nil)
        #expect(try await lastSent().image == Data())
        #expect(try await lastSent().imageDigest == Data())
        #expect(try await stored().imageVersion == 2)

        // An image received from another device is stored with the version it came with.
        try await update(members: ["alice", "bob", "carol"], image: picture, imageVersion: 7)
        #expect(try await stored().image == picture)
        #expect(try await stored().imageVersion == 7)
        #expect(try await lastSent().imageVersion == 7)
        #expect(await delegate.channelMetadata.count == 4)

        await session.shutdown()
    }
}

/// Records the metadata of each channel synchronization instead of sending it.
private actor SynchronizationCapturingDelegate: MessagingPolicy, RecoveryObserver {
    var channelMetadata: [Data] = []

    func synchronizeCommunication(recipient: MessageRecipient, sharedIdentifier _: String, metadata: Data) async throws {
        if case .channel = recipient {
            channelMetadata.append(metadata)
        }
    }

    func requestMetadata(recipient _: MessageRecipient) async throws {}
    func requestFriendshipStateChange(recipient _: MessageRecipient, blockData _: Data?, metadata _: Data, currentState _: FriendshipMetadata.State) async throws {}
    func deliveryStateChanged(recipient _: MessageRecipient, metadata _: Data) async throws {}
    func createdContact(recipient _: MessageRecipient) async throws {}
    func editMessage(recipient _: MessageRecipient, metadata _: Data) async throws {}
    nonisolated func shouldPersist(transportInfo _: Data?) -> Bool { true }
    nonisolated func shouldReplayNonPersistentOutbound(transportInfo _: Data?) -> Bool { false }
    nonisolated func isInboundRecoveryPlaceholder(transportInfo _: Data?) -> Bool { false }
    func retrieveUserInfo(_: Data?) async -> (secretName: String, deviceId: String)? { nil }
    nonisolated func updateCryptoMessageMetadata(_ message: CryptoMessage, sharedMessageId _: String) -> CryptoMessage { message }
    func updateEncryptableMessageMetadata(_ message: EncryptedMessage, transportInfo _: Data?, identity _: SessionIdentity, recipient _: MessageRecipient) async -> EncryptedMessage { message }
    nonisolated func shouldFinishCommunicationSynchronization(_: Data?) -> Bool { false }
    func processMessage(_: CryptoMessage, senderSecretName _: String, senderDeviceId _: UUID) async -> Bool { true }
    func shouldSendAutomaticDeliveryReceipts() async -> Bool { false }

    func inboundRecoveryDeferred(senderSecretName _: String, senderDeviceId _: UUID, failedSharedMessageId _: String, failureClass _: String) async {}
    func inboundMessagePendingRecovery(senderSecretName _: String, senderDeviceId _: UUID, sharedMessageId _: String) async {}
    func inboundCiphertextAccepted(sharedMessageId _: String) async {}
    func inboundContentUnrecoverable(senderSecretName _: String, senderDeviceId _: UUID, sharedMessageId _: String) async {}
    func outboundMessageUnrecoverable(sharedMessageId _: String, reason _: String) async {}
    func reestablishmentEpisodeDidEnd(senderSecretName _: String, senderDeviceId _: UUID) async {}
    func linkedDeviceReportedPotentialCompromise(deviceId _: UUID, intentId _: UUID?) async {}
    func peerAccountIdentityChanged(secretName _: String, deviceId _: UUID, failedSharedMessageId _: String?) async {}
    func shouldSuppressInboundRecoveryFromSender(_: String) async -> Bool { false }
    func preferredOnlinePeerDeviceId(for _: String) async -> UUID? { nil }
}

