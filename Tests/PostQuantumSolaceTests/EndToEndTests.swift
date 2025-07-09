//
//  EndToEndTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-19.
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
import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailAsyncSequence
import NeedleTailCrypto
@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels
import Testing

@Suite(.serialized)
actor EndToEndTests {
    let crypto = NeedleTailCrypto()
    var _senderSession = PQSSession()
    var _recipientSession = PQSSession()
    let sMockUserData: MockUserData
    let rMockUserData: MockUserData
    let transport = _MockTransportDelegate()
    var senderReceiver = ReceiverDelegate()
    var recipientReceiver = ReceiverDelegate()
    let bobProcessedRotated = ContinuationSignal()
    let aliceProcessedRotated = ContinuationSignal()
    let aliceProcessedBobRotation = ContinuationSignal() // NEW SIGNAL
    
    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet { transport.aliceStreamContinuation = aliceStreamContinuation }
    }
    
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet { transport.bobStreamContinuation = bobStreamContinuation }
    }
    private let bobProcessedThree = ContinuationSignal()
    private let aliceProcessedSix = ContinuationSignal()
    
    init() {
        sMockUserData = MockUserData(session: _senderSession)
        rMockUserData = MockUserData(session: _recipientSession)
    }
    
    // MARK: - Helper Methods
    
    func createSenderStore() -> MockIdentityStore {
        sMockUserData.identityStore(isSender: true)
    }
    
    func createRecipientStore() -> MockIdentityStore {
        rMockUserData.identityStore(isSender: false)
    }
    
    func createSenderSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt1"
        await _senderSession.setLogLevel(.trace)
        await _senderSession.setDatabaseDelegate(conformer: store)
        await _senderSession.setTransportDelegate(conformer: transport)
        await _senderSession.setPQSSessionDelegate(conformer: SessionDelegate())
        
        _senderSession.isViable = true
        await _senderSession.setReceiverDelegate(conformer: senderReceiver)
        transport.publishableName = sMockUserData.ssn
        _senderSession = try await _senderSession.createSession(secretName: sMockUserData.ssn, appPassword: sMockUserData.sap) {}
        await _senderSession.setAppPassword(sMockUserData.sap)
        _senderSession = try await _senderSession.startSession(appPassword: sMockUserData.sap)
        try await senderReceiver.setKey(_senderSession.getDatabaseSymmetricKey())
    }
    
    func createRecipientSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt2"
        await _recipientSession.setLogLevel(.trace)
        await _recipientSession.setDatabaseDelegate(conformer: store)
        await _recipientSession.setTransportDelegate(conformer: transport)
        await _recipientSession.setPQSSessionDelegate(conformer: SessionDelegate())
        
        _recipientSession.isViable = true
        await _recipientSession.setReceiverDelegate(conformer: recipientReceiver)
        transport.publishableName = rMockUserData.rsn
        _recipientSession = try await _recipientSession.createSession(secretName: rMockUserData.rsn, appPassword: rMockUserData.sap) {}
        await _recipientSession.setAppPassword(rMockUserData.sap)
        _recipientSession = try await _recipientSession.startSession(appPassword: rMockUserData.sap)
        try await recipientReceiver.setKey(_recipientSession.getDatabaseSymmetricKey())
    }
    
    // MARK: - Test Methods
    
    @Test
    func ratchetManagerReCreation() async throws {
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        
        await #expect(throws: Never.self, "Session initialization and first message should complete without errors") {
            let senderStore = self.createSenderStore()
            let recipientStore = self.createRecipientStore()
            
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            
            try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message One", metadata: [:])
        }
        Task {
            await #expect(throws: Never.self, "Alice's message processing loop should handle received messages without errors") {
                var aliceIterations = 0
                for await received in aliceStream {
                    aliceIterations += 1
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    if aliceIterations == 2 {
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Four", metadata: [:])
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Five", metadata: [:])
                    }
                }
            }
        }
        
        await #expect(throws: Never.self, "Bob's message processing loop should handle received messages and send replies without errors") {
            var bobIterations = 0
            for await received in bobStream {
                bobIterations += 1
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
                
                if bobIterations == 1 {
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Three", metadata: [:])
                }
                
                if bobIterations == 3 {
                    self.aliceStreamContinuation?.finish()
                    self.bobStreamContinuation?.finish()
                }
            }
            await self._senderSession.shutdown()
            await self._recipientSession.shutdown()
        }
    }
    
    @Test
    func thousandMessageExchange() async throws {
        let totalMessages = 1000
        
        // 1) Create stores & streams
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        await #expect(throws: Never.self, "Sessions should initialize and Alice should send the first message without errors") {
            // 2) Initialize sessions (PQXDH handshake)
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            
            // 3) Kick off the very first message from Alice → Bob
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "1",
                metadata: [:]
            )
        }
        // 4) Bob's receive‑and‑reply loop
        Task {
            await #expect(throws: Never.self, "Bob's receive-and-reply loop should process and respond to messages without errors") {
                var bobReceivedCount = 0
                for await received in bobStream {
                    bobReceivedCount += 1
                    
                    // Process incoming
                    try await self._recipientSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId
                    )
                    
                    // If Bob still needs to send more, reply with next number
                    if bobReceivedCount < totalMessages {
                        let next = bobReceivedCount * 2 // Bob sends even‑numbered msgs
                        try await self._recipientSession.writeTextMessage(
                            recipient: .nickname("alice"),
                            text: "\(next)",
                            metadata: [:]
                        )
                    } else {
                        // Bob got all his 1 000; close his stream
                        self.bobStreamContinuation?.finish()
                        self.aliceStreamContinuation?.finish()
                    }
                }
            }
        }
        
        // 5) Alice's receive‑and‑reply loop
        var aliceReceivedCount = 0
        for await received in aliceStream {
            aliceReceivedCount += 1
            await #expect(throws: Never.self, "Alice's receive-and-reply loop should process and respond to messages without errors") {
                // Process incoming
                try await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId
                )
                
                // If Alice still needs to send more, reply with next odd number
                if aliceReceivedCount < totalMessages {
                    let next = aliceReceivedCount * 2 + 1 // Alice sends odd‑numbered msgs
                    try await self._senderSession.writeTextMessage(
                        recipient: .nickname("bob"),
                        text: "\(next)",
                        metadata: [:]
                    )
                }
            }
        }
        
        // 6) Cleanly shut down both sessions
        await _senderSession.shutdown()
        await _recipientSession.shutdown()
    }
    
    @Test
    func outOfOrderMessagesHandledCorrectly() async throws {
        await #expect(throws: Never.self, "Out-of-order test: session setup, message send, and out-of-order receive should not throw") {
            let senderStore = self.createSenderStore()
            let recipientStore = self.createRecipientStore()
            
            // 1) Set up a single AsyncStream on the recipient side
            let stream = AsyncStream<ReceivedMessage> { continuation in
                self.bobStreamContinuation = continuation
            }
            
            // 2) Do the PQXDH handshake before sending any data
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            
            // 3) Prepare 79 distinct messages
            let messages = (0 ..< 79).map { "Out‑of‑order Message \($0)" }
            
            // 4) Send them all (in-order) from Alice → Bob
            for text in messages {
                try await self._senderSession.writeTextMessage(
                    recipient: .nickname("bob"),
                    text: text,
                    metadata: [:]
                )
            }
            
            // 5) Collect exactly 79 ReceivedMessage frames from the stream …
            var collected: [ReceivedMessage] = []
            for await received in stream {
                collected.append(received)
                if collected.count == messages.count {
                    // Once we have all 79, stop listening
                    self.bobStreamContinuation?.finish()
                    break
                }
            }
            
            // 6) Now actually feed them into Bob's ratchet out‑of‑order:
            //    first the very first message he should ever see…
            let first = collected.removeFirst()
            try await self._recipientSession.receiveMessage(
                message: first.message,
                sender: first.sender,
                deviceId: first.deviceId,
                messageId: first.messageId
            )
            
            //    …then the rest in a random order:
            for msg in collected.shuffled() {
                try await self._recipientSession.receiveMessage(
                    message: msg.message,
                    sender: msg.sender,
                    deviceId: msg.deviceId,
                    messageId: msg.messageId
                )
            }
        }
    }
    
    @Test
    func testRatchetManagerReCreationReKey() async throws {
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        await #expect(throws: Never.self, "Session initialization and first message should complete without errors (rekey test)") {
            try await self.createSenderSession(store: senderStore)
            try await self.createRecipientSession(store: recipientStore)
            try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message One", metadata: [:])
        }
        // Alice's receive loop
        Task {
            await #expect(throws: Never.self, "Alice's message processing loop should handle received messages and key rotation without errors") {
                var aliceIterations = 0
                for await received in aliceStream {
                    aliceIterations += 1
                    try await self._senderSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                    // First user message (after protocol message)
                    if aliceIterations == 2 {
                        try await self._senderSession.rotateKeysOnPotentialCompromise()
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Three", metadata: [:])
                        await self.bobProcessedRotated.wait()
                    }
                    // After Bob's post-rotation message
                    if aliceIterations == 3 {
                        await self.aliceProcessedBobRotation.signal()
                        self.aliceStreamContinuation?.finish()
                        self.bobStreamContinuation?.finish()
                    }
                }
                await self._senderSession.shutdown()
            }
        }
        // Bob's receive loop
        var bobIterations = 0
        for await received in bobStream {
            bobIterations += 1
            await #expect(throws: Never.self, "Bob's message processing loop should handle received messages, replies, and key rotation without errors") {
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
                // First user message (after protocol message)
                if bobIterations == 2 {
                    await self.bobProcessedRotated.signal()
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                }
                // After Alice's post-rotation message
                if bobIterations == 3 {
                    try await self._recipientSession.rotateKeysOnPotentialCompromise()
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Four", metadata: [:])
                    await self.aliceProcessedBobRotation.wait()
                    self.bobStreamContinuation?.finish()
                    self.aliceStreamContinuation?.finish()
                }
            }
        }
        await self._recipientSession.shutdown()
    }
}

actor ContinuationSignal {
    private var continuation: CheckedContinuation<Void, Never>?
    private var pendingSignals = 0
    
    func wait() async {
        if pendingSignals > 0 {
            pendingSignals -= 1
            return
        }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            continuation = c
        }
    }
    
    func signal() {
        if let c = continuation {
            continuation = nil
            c.resume()
        } else {
            pendingSignals += 1
        }
    }
}

// MARK: - Supporting Types

struct SessionDelegate: PQSSessionDelegate {
    
    func synchronizeCommunication(recipient _: SessionModels.MessageRecipient, sharedIdentifier _: String) async throws {}
    func requestFriendshipStateChange(recipient: SessionModels.MessageRecipient, blockData: Data?, metadata: BSON.Document, currentState: SessionModels.FriendshipMetadata.State) async throws {}
    func deliveryStateChanged(recipient _: SessionModels.MessageRecipient, metadata _: BSON.Document) async throws {}
    func contactCreated(recipient _: SessionModels.MessageRecipient) async throws {}
    func requestMetadata(recipient _: SessionModels.MessageRecipient) async throws {}
    func editMessage(recipient _: SessionModels.MessageRecipient, metadata _: BSON.Document) async throws {}
    func shouldPersist(transportInfo _: Data?) -> Bool { true }
    func retrieveUserInfo(_: Data?) async -> (secretName: String, deviceId: String)? { nil }
    func updateCryptoMessageMetadata(_ message: SessionModels.CryptoMessage, sharedMessageId _: String) -> SessionModels.CryptoMessage { message }
    func updateEncryptableMessageMetadata(_ message: SessionModels.EncryptedMessage, transportInfo _: Data?, identity _: DoubleRatchetKit.SessionIdentity, recipient _: SessionModels.MessageRecipient) async -> SessionModels.EncryptedMessage { message }
    func shouldFinishCommunicationSynchronization(_: Data?) -> Bool { false }
    func processUnpersistedMessage(_: SessionModels.CryptoMessage, senderSecretName _: String, senderDeviceId _: UUID) async -> Bool { true }
}

actor ReceiverDelegate: EventReceiver {
    
    var key: SymmetricKey?
    
    func setKey(_ key: SymmetricKey) async {
        self.key = key
    }
    
    func createdMessage(_ message: SessionModels.EncryptedMessage) async {}
    func updatedMessage(_: SessionModels.EncryptedMessage) async {}
    func updateContact(_: SessionModels.Contact) async throws {}
    func contactMetadata(changed _: SessionModels.Contact) async {}
    func deletedMessage(_: SessionModels.EncryptedMessage) async {}
    func createdContact(_: SessionModels.Contact) async throws {}
    func removedContact(_: String) async throws {}
    func synchronize(contact _: SessionModels.Contact, requestFriendship _: Bool) async throws {}
    func transportContactMetadata() async throws {}
    func updatedCommunication(_: SessionModels.BaseCommunication, members _: Set<String>) async {}
}

struct ReceivedMessage {
    let message: SignedRatchetMessage
    let sender: String
    let deviceId: UUID
    let messageId: String
}

final class _MockTransportDelegate: SessionTransport, @unchecked Sendable {
    struct IdentifiableSignedoneTimePublicKey {
        let id: String
        var keys: [UserConfiguration.SignedOneTimePublicKey]
    }
    
    struct IdentifiableSignedKyberOneTimeKey {
        let id: String
        var keys: [UserConfiguration.SignedPQKemOneTimeKey]
    }
    
    // MARK: - Properties
    
    var oneTimePublicKeyPairs = [IdentifiableSignedoneTimePublicKey]()
    var kyberOneTimeKeyPairs = [IdentifiableSignedKyberOneTimeKey]()
    var publishableName: String!
    var userConfigurations = [User]()
    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    
    // MARK: - Used Methods
    
    func fetchOneTimeKeys(for secretName: String, deviceId _: String) async throws -> SessionModels.OneTimeKeys {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        
        guard let oneTimeKeyPairIndex = oneTimePublicKeyPairs.firstIndex(where: { $0.id == secretName }) else { fatalError() }
        let oneTimeKeyPair = oneTimePublicKeyPairs[oneTimeKeyPairIndex]
        guard let publicKey = try oneTimeKeyPair.keys.last?.verified(using: signingKey) else { fatalError() }
        oneTimePublicKeyPairs.remove(at: oneTimeKeyPairIndex)
        
        guard let kyberKeyPairIndex = kyberOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) else { fatalError() }
        let kyberKeyPair = kyberOneTimeKeyPairs[kyberKeyPairIndex]
        guard let kyberKey = try kyberKeyPair.keys.last?.verified(using: signingKey) else { fatalError() }
        kyberOneTimeKeyPairs.remove(at: kyberKeyPairIndex)
        
        return SessionModels.OneTimeKeys(curve: publicKey, kyber: kyberKey)
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId _: String, type _: KeysType) async throws -> [UUID] {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        let filtered = oneTimePublicKeyPairs.filter { $0.id == secretName }
        var verifiedIDs: [UUID] = []
        for key in filtered {
            for oneTimeKey in key.keys {
                if let verifiedKey = try? oneTimeKey.verified(using: signingKey) {
                    verifiedIDs.append(verifiedKey.id)
                }
            }
        }
        return verifiedIDs
    }
    
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient identity: UUID) async throws {
        userConfigurations.append(.init(secretName: publishableName, deviceId: identity, config: configuration))
        oneTimePublicKeyPairs.append(IdentifiableSignedoneTimePublicKey(id: publishableName, keys: configuration.signedOneTimePublicKeys))
        kyberOneTimeKeyPairs.append(IdentifiableSignedKyberOneTimeKey(id: publishableName, keys: configuration.signedPQKemOneTimePublicKeys))
    }
    
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
        guard let sender = userConfigurations.first(where: { $0.secretName != metadata.secretName }) else { return }
        guard let recipient = userConfigurations.first(where: { $0.secretName == metadata.secretName }) else { return }
        let received = ReceivedMessage(
            message: message,
            sender: sender.secretName,
            deviceId: sender.deviceId,
            messageId: metadata.sharedMessageId
        )
        if recipient.secretName == "alice" {
            aliceStreamContinuation?.yield(received)
        } else if recipient.secretName == "bob" {
            bobStreamContinuation?.yield(received)
        }
    }
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        guard let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName })?.config else {
            throw PQSSession.SessionErrors.userNotFound
        }
        return userConfiguration
    }
    
    func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
        guard let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName })?.config else {
            throw PQSSession.SessionErrors.configurationError
        }
        return userConfiguration
    }
    
    func publishRotatedKeys(for secretName: String, deviceId: String, rotated keys: SessionModels.RotatedPublicKeys) async throws {
        guard let index = userConfigurations.firstIndex(where: { $0.secretName == secretName }) else { fatalError() }
        var userConfig = userConfigurations[index]
        let oldSigningKey = try Curve25519SigningPublicKey(rawRepresentation: userConfig.config.signingPublicKey)
        guard let deviceIndex = userConfig.config.signedDevices.firstIndex(where: {
            guard let verified = try? $0.verified(using: oldSigningKey) else { return false }
            return verified.deviceId.uuidString == deviceId
        }) else { fatalError() }
        userConfig.config.signedDevices[deviceIndex] = keys.signedDevice
        userConfig.config.signingPublicKey = keys.pskData
        userConfigurations[index] = userConfig
    }
    
    // MARK: - Unused Methods (Stubs)
    
    func receiveMessage() async throws -> String { "" }
    func updateOneTimeKeys(for _: String, deviceId _: String, keys _: [SessionModels.UserConfiguration.SignedOneTimePublicKey]) async throws {}
    func updateOneTimePQKemKeys(for _: String, deviceId _: String, keys _: [SessionModels.UserConfiguration.SignedPQKemOneTimeKey]) async throws {}
    func batchDeleteOneTimeKeys(for _: String, with _: String, type _: SessionModels.KeysType) async throws {}
    func deleteOneTimeKeys(for _: String, with _: String, type _: SessionModels.KeysType) async throws {}
    func createUploadPacket(secretName _: String, deviceId _: UUID, recipient _: SessionModels.MessageRecipient, metadata _: BSON.Document) async throws {}
    func notifyIdentityCreation(for _: String, keys _: SessionModels.OneTimeKeys) async throws {}
}

final class MockIdentityStore: PQSSessionStore, @unchecked Sendable {
    // MARK: - Properties
    
    var sessionContext: Data?
    var identities = [SessionIdentity]()
    let crypto = NeedleTailCrypto()
    var mockUserData: MockUserData
    let session: PQSSession
    let isSender: Bool
    var localDeviceSalt: String?
    var encyrptedConfigurationForTesting = Data()
    var createdMessages = [EncryptedMessage]()
    
    init(mockUserData: MockUserData, session: PQSSession, isSender: Bool) {
        self.mockUserData = mockUserData
        self.session = session
        self.isSender = isSender
    }
    
    // MARK: - Used Methods
    
    func createLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func fetchLocalSessionContext() async throws -> Data { sessionContext! }
    func updateLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func deleteLocalSessionContext() async throws { sessionContext = nil }
    func fetchLocalDeviceSalt(keyData: Data) async throws -> Data { keyData + "salt".data(using: .utf8)! }
    func deleteLocalDeviceSalt() async throws {}
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] { identities }
    func updateSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {
        identities.removeAll(where: { $0.id == session.id })
        identities.append(session)
    }
    
    func createSessionIdentity(_ session: SessionIdentity) async throws { identities.append(session) }
    func fetchLocalDeviceSalt() async throws -> String {
        guard let salt = localDeviceSalt else { throw PQSSession.SessionErrors.saltError }
        return salt
    }
    
    func findLocalDeviceConfiguration() async throws -> Data { encyrptedConfigurationForTesting }
    func createLocalDeviceConfiguration(_ configuration: Data) async throws { encyrptedConfigurationForTesting = configuration }
    
    // MARK: - Unused Methods (Stubs)
    
    func removeContact(_: UUID) async throws {}
    func deleteContact(_: UUID) async throws {}
    func deleteSessionIdentity(_: UUID) async throws {}
    func createMediaJob(_: SessionModels.DataPacket) async throws {}
    func fetchAllMediaJobs() async throws -> [SessionModels.DataPacket] { [] }
    func fetchMediaJob(id _: UUID) async throws -> SessionModels.DataPacket? { nil }
    func deleteMediaJob(_: UUID) async throws {}
    func fetchContacts() async throws -> [SessionModels.ContactModel] { [] }
    func createContact(_: SessionModels.ContactModel) async throws {}
    func updateContact(_: SessionModels.ContactModel) async throws {}
    func fetchCommunications() async throws -> [SessionModels.BaseCommunication] { [] }
    func createCommunication(_: SessionModels.BaseCommunication) async throws {}
    func updateCommunication(_: SessionModels.BaseCommunication) async throws {}
    func removeCommunication(_: SessionModels.BaseCommunication) async throws {}
    func deleteCommunication(_: SessionModels.BaseCommunication) async throws {}
    func fetchMessages(sharedCommunicationId _: UUID) async throws -> [MessageRecord] { [] }
    func fetchMessage(id _: UUID) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
    }
    
    func fetchMessage(sharedId _: String) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
    }
    
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        createdMessages.append(message)
    }
    func updateMessage(_: SessionModels.EncryptedMessage, symmetricKey _: SymmetricKey) async throws {}
    func removeMessage(_: SessionModels.EncryptedMessage) async throws {}
    func deleteMessage(_: SessionModels.EncryptedMessage) async throws {}
    func streamMessages(sharedIdentifier _: UUID) async throws -> (AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>, AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>.Continuation?) {
        let stream = AsyncThrowingStream<SessionModels.EncryptedMessage, any Error> { continuation in
            for i in 1 ... 5 {
                if let message = try? SessionModels.EncryptedMessage(id: UUID(), communicationId: UUID(), sessionContextId: i, sharedId: "123", sequenceNumber: 1, data: Data()) {
                    continuation.yield(message)
                }
            }
            continuation.finish()
        }
        return (stream, nil)
    }
    
    func messageCount(sharedIdentifier _: UUID) async throws -> Int { 1 }
    func readJobs() async throws -> [SessionModels.JobModel] { [] }
    func fetchJobs() async throws -> [SessionModels.JobModel] { [] }
    func createJob(_: SessionModels.JobModel) async throws {}
    func updateJob(_: SessionModels.JobModel) async throws {}
    func removeJob(_: SessionModels.JobModel) async throws {}
    func deleteJob(_: SessionModels.JobModel) async throws {}
    func findMediaJobs(for _: String, symmetricKey _: SymmetricKey) async throws -> [SessionModels.DataPacket] { [] }
    func fetchMediaJobs(recipient _: String, symmetricKey _: SymmetricKey) async throws -> [SessionModels.DataPacket] { [] }
    func findMediaJob(for _: String, symmetricKey _: SymmetricKey) async throws -> SessionModels.DataPacket? { nil }
    func fetchMediaJob(synchronizationIdentifier _: String, symmetricKey _: SymmetricKey) async throws -> SessionModels.DataPacket? { nil }
}

struct MockUserData {
    var senderPublicIdentity: UUID?
    let ssn = "alice"
    let sap = "123"
    var receiverPublicIdentity = UUID()
    let sci = 0
    let dn = "deviceName"
    let rsn = "bob"
    let lid = UUID()
    let ntm = CryptoMessage(
        text: "Some Message",
        metadata: [:],
        recipient: .nickname("bob"),
        sentDate: Date(),
        destructionTime: nil
    )
    let smi = "123456789"
    let session: PQSSession
    
    init(session: PQSSession) {
        self.session = session
    }
    
    func identityStore(isSender: Bool) -> MockIdentityStore {
        MockIdentityStore(mockUserData: self, session: session, isSender: isSender)
    }
}

struct User {
    let secretName: String
    let deviceId: UUID
    var config: UserConfiguration
}

extension Data {
    var hexString: String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}

