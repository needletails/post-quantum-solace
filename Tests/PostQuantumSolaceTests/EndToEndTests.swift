//
//  EndToEndTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/19/24.
//
@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels
import Crypto
import BSON
import Testing
import Foundation
import NeedleTailAsyncSequence
import NeedleTailCrypto
import DoubleRatchetKit

@Suite(.serialized)
class EndToEndTests: @unchecked Sendable {
    
    let crypto = NeedleTailCrypto()
    let _senderSession = PQSSession()
    let _recipientSession = PQSSession()
    let sMockUserData: MockUserData
    let rMockUserData: MockUserData
    let transport = _MockTransportDelegate()
    
    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet { transport.aliceStreamContinuation = aliceStreamContinuation }
    }
    
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet { transport.bobStreamContinuation = bobStreamContinuation }
    }
    
    init() {
        self.sMockUserData = MockUserData(session: _senderSession)
        self.rMockUserData = MockUserData(session: _recipientSession)
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
        await _senderSession.setReceiverDelegate(conformer: ReceiverDelegate())
        transport.publishableName = sMockUserData.ssn
        _ = try await _senderSession.createSession(secretName: sMockUserData.ssn, appPassword: sMockUserData.sap) {}
        await _senderSession.setAppPassword(sMockUserData.sap)
        _ = try await _senderSession.startSession(appPassword: sMockUserData.sap)
    }
    
    func createRecipientSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt2"
        await _recipientSession.setLogLevel(.trace)
        await _recipientSession.setDatabaseDelegate(conformer: store)
        await _recipientSession.setTransportDelegate(conformer: transport)
        await _recipientSession.setPQSSessionDelegate(conformer: SessionDelegate())
        
        _recipientSession.isViable = true
        await _recipientSession.setReceiverDelegate(conformer: ReceiverDelegate())
        transport.publishableName = rMockUserData.rsn
        _ = try await _recipientSession.createSession(secretName: rMockUserData.rsn, appPassword: rMockUserData.sap) {}
        await _recipientSession.setAppPassword(rMockUserData.sap)
        _ = try await _recipientSession.startSession(appPassword: rMockUserData.sap)
    }
    
    // MARK: - Test Methods
    @Test
    func testRatchetManagerReCreation() async throws {
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
                        messageId: received.messageId)
                    
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
                    messageId: received.messageId)
                
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
    func testThousandMessageExchange() async throws {
        let totalMessages = 1_000
        
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
                        let next = bobReceivedCount * 2  // Bob sends even‑numbered msgs
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
                    let next = aliceReceivedCount * 2 + 1  // Alice sends odd‑numbered msgs
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
    func testOutOfOrderMessagesHandledCorrectly() async throws {
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
            let messages = (0..<79).map { "Out‑of‑order Message \($0)" }
            
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
                messageId: first.messageId)
            
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
                    
                    if aliceIterations == 1 {
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Five", metadata: [:])
                    }
                    
                    if aliceIterations == 2 {
                        try await self._senderSession.rotateKeysOnPotentialCompromise()
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Five", metadata: [:])
                    }
                    
                    if aliceIterations == 8 {
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Five", metadata: [:])
                        try await self._senderSession.writeTextMessage(recipient: .nickname("bob"), text: "Message Five", metadata: [:])
                    }
                }
            }
        }
        
        var bobIterations = 0
        for await received in bobStream {
            bobIterations += 1
            await #expect(throws: Never.self, "Bob's message processing loop should handle received messages, replies, and key rotation without errors") {
                try await self._recipientSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
                
                if bobIterations == 1 {
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                }
                
                if bobIterations == 2 {
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                }
                
                if bobIterations == 3 {
                    try await self._recipientSession.rotateKeysOnPotentialCompromise()
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                    try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"), text: "Message Two", metadata: [:])
                }
            }
            if bobIterations == 4 {
                aliceStreamContinuation?.finish()
                bobStreamContinuation?.finish()
            }
        }
        await _senderSession.shutdown()
        await _recipientSession.shutdown()
    }
}

// MARK: - Supporting Types

struct SessionDelegate: PQSSessionDelegate {
    func communicationSynchonization(recipient: SessionModels.MessageRecipient, sharedIdentifier: String) async throws {}
    func blockUnblock(recipient: SessionModels.MessageRecipient, data: Data?, metadata: BSON.Document, myState: SessionModels.FriendshipMetadata.State) async throws {}
    func deliveryStateChanged(recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {}
    func contactCreated(recipient: SessionModels.MessageRecipient) async throws {}
    func requestMetadata(recipient: SessionModels.MessageRecipient) async throws {}
    func editMessage(recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {}
    func shouldPersist(transportInfo: Data?) -> Bool { true }
    func getUserInfo(_ transportInfo: Data?) async throws -> (secretName: String, deviceId: String)? { nil }
    func updateCryptoMessageMetadata(_ message: SessionModels.CryptoMessage, sharedMessageId: String) throws -> SessionModels.CryptoMessage { message }
    func updateEncryptableMessageMetadata(_ message: SessionModels.EncryptedMessage, transportInfo: Data?, identity: DoubleRatchetKit.SessionIdentity, recipient: SessionModels.MessageRecipient) async throws -> SessionModels.EncryptedMessage { message }
    func shouldFinishCommunicationSynchronization(_ transportInfo: Data?) -> Bool { false }
    func processUnpersistedMessage(_ message: SessionModels.CryptoMessage, senderSecretName: String, senderDeviceId: UUID) async throws -> Bool { true }
}

struct ReceiverDelegate: EventReceiver {
    func createdMessage(_ message: SessionModels.EncryptedMessage) async {}
    func updatedMessage(_ message: SessionModels.EncryptedMessage) async {}
    func updateContact(_ contact: SessionModels.Contact) async throws {}
    func contactMetadata(changed for: SessionModels.Contact) async {}
    func deletedMessage(_ message: SessionModels.EncryptedMessage) async {}
    func createdContact(_ contact: SessionModels.Contact) async throws {}
    func removedContact(_ secretName: String) async throws {}
    func synchronize(contact: SessionModels.Contact, requestFriendship: Bool) async throws {}
    func transportContactMetadata() async throws {}
    func updatedCommunication(_ model: SessionModels.BaseCommunication, members: Set<String>) async {}
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
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> SessionModels.OneTimeKeys {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        
        guard let oneTimeKeyPairIndex = oneTimePublicKeyPairs.firstIndex(where: { $0.id == secretName }) else { fatalError() }
        let oneTimeKeyPair = oneTimePublicKeyPairs[oneTimeKeyPairIndex]
        guard let publicKey = try oneTimeKeyPair.keys.last?.verified(using: signingKey) else { fatalError() }
        oneTimePublicKeyPairs.remove(at: oneTimeKeyPairIndex)
        
        guard let kyberKeyPairIndex = kyberOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) else { fatalError() }
        let kyberKeyPair = kyberOneTimeKeyPairs[kyberKeyPairIndex]
        guard let kyberKey = try kyberKeyPair.keys.last?.pqKemVerified(using: signingKey) else { fatalError() }
        kyberOneTimeKeyPairs.remove(at: kyberKeyPairIndex)
        
        return SessionModels.OneTimeKeys(curve: publicKey, kyber: kyberKey)
    }
    
    func fetchOneTimeKeyIdentites(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.signingPublicKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        let filtered = oneTimePublicKeyPairs.filter({ $0.id == secretName })
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
        self.userConfigurations.append(.init(secretName: publishableName, deviceId: identity, config: configuration))
        oneTimePublicKeyPairs.append(IdentifiableSignedoneTimePublicKey(id: publishableName, keys: configuration.signedOneTimePublicKeys))
        kyberOneTimeKeyPairs.append(IdentifiableSignedKyberOneTimeKey(id: publishableName, keys: configuration.signedPQKemOneTimePublicKeys))
    }
    
    func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
        guard let sender = userConfigurations.first(where: { $0.secretName != metadata.secretName }) else { return }
        let received = ReceivedMessage(message: message, sender: sender.secretName, deviceId: sender.deviceId, messageId: metadata.sharedMessageIdentifier)
        if sender.secretName == "alice" {
            bobStreamContinuation?.yield(received)
        } else {
            aliceStreamContinuation?.yield(received)
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
        guard let index = self.userConfigurations.firstIndex(where: { $0.secretName == secretName }) else { fatalError() }
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
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedOneTimePublicKey]) async throws {}
    func updateOneTimeKyberKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedPQKemOneTimeKey]) async throws {}
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {}
    func deleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {}
    func createUploadPacket(secretName: String, deviceId: UUID, recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {}
    func notifyIdentityCreation(for secretName: String, keys: SessionModels.OneTimeKeys) async throws {}
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
    
    init(mockUserData: MockUserData, session: PQSSession, isSender: Bool) {
        self.mockUserData = mockUserData
        self.session = session
        self.isSender = isSender
    }
    
    // MARK: - Used Methods
    func createLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func findLocalSessionContext() async throws -> Data { return sessionContext! }
    func updateLocalSessionContext(_ data: Data) async throws { sessionContext = data }
    func deleteLocalSessionContext() async throws { sessionContext = nil }
    func findLocalDeviceSalt(keyData: Data) async throws -> Data { keyData + "salt".data(using: .utf8)! }
    func deleteLocalDeviceSalt() async throws {}
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] { return identities }
    func updateSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {
        identities.removeAll(where: { $0.id == session.id })
        identities.append(session)
    }
    func createSessionIdentity(_ session: SessionIdentity) async throws { identities.append(session) }
    func findLocalDeviceSalt() async throws -> String {
        guard let salt = localDeviceSalt else { throw PQSSession.SessionErrors.saltError }
        return salt
    }
    func findLocalDeviceConfiguration() async throws -> Data { encyrptedConfigurationForTesting }
    func createLocalDeviceConfiguration(_ configuration: Data) async throws { encyrptedConfigurationForTesting = configuration }
    
    // MARK: - Unused Methods (Stubs)
    func removeContact(_ id: UUID) async throws {}
    func createMediaJob(_ packet: SessionModels.DataPacket) async throws {}
    func findAllMediaJobs() async throws -> [SessionModels.DataPacket] { [] }
    func findMediaJob(_ id: UUID) async throws -> SessionModels.DataPacket? { nil }
    func deleteMediaJob(_ id: UUID) async throws {}
    func removeSessionIdentity(_ id: UUID) async throws {}
    func fetchContacts() async throws -> [SessionModels.ContactModel] { [] }
    func createContact(_ contact: SessionModels.ContactModel) async throws {}
    func updateContact(_ contact: SessionModels.ContactModel) async throws {}
    func fetchCommunications() async throws -> [SessionModels.BaseCommunication] { [] }
    func createCommunication(_ type: SessionModels.BaseCommunication) async throws {}
    func updateCommunication(_ type: SessionModels.BaseCommunication) async throws {}
    func removeCommunication(_ type: SessionModels.BaseCommunication) async throws {}
    func fetchMessages(sharedCommunicationId: UUID) async throws -> [_WrappedPrivateMessage] { [] }
    func fetchMessage(byId messageId: UUID) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
    }
    func fetchMessage(by sharedMessageId: String) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
    }
    func createMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
    func updateMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
    func removeMessage(_ message: SessionModels.EncryptedMessage) async throws {}
    func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>, AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>.Continuation?) {
        let stream = AsyncThrowingStream<SessionModels.EncryptedMessage, any Error> { continuation in
            for i in 1...5 {
                if let message = try? SessionModels.EncryptedMessage(id: UUID(), communicationId: UUID(), sessionContextId: i, sharedId: "123", sequenceNumber: 1, data: Data()) {
                    continuation.yield(message)
                }
            }
            continuation.finish()
        }
        return (stream, nil)
    }
    func messageCount(for sharedIdentifier: UUID) async throws -> Int { 1 }
    func readJobs() async throws -> [SessionModels.JobModel] { [] }
    func createJob(_ job: SessionModels.JobModel) async throws {}
    func updateJob(_ job: SessionModels.JobModel) async throws {}
    func removeJob(_ job: SessionModels.JobModel) async throws {}
    func findMediaJobs(for recipient: String, symmetricKey: SymmetricKey) async throws -> [SessionModels.DataPacket] { [] }
    func findMediaJob(for synchronizationIdentifier: String, symmetricKey: SymmetricKey) async throws -> SessionModels.DataPacket? { nil }
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
        destructionTime: nil)
    let smi = "123456789"
    let session: PQSSession
    
    init(session: PQSSession) {
        self.session = session
    }
    
    func identityStore(isSender: Bool) -> MockIdentityStore {
        return MockIdentityStore(mockUserData: self, session: session, isSender: isSender)
    }
}

struct User {
    let secretName: String
    let deviceId: UUID
    var config: UserConfiguration
}

extension Data {
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
