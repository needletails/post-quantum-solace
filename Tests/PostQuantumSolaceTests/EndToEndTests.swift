//
//  EndToEndTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/19/24.
//
@testable import CryptoSession
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
    let _senderSession = CryptoSession()
    let _recipientSession = CryptoSession()
    let sMockUserData: MockUserData
    let rMockUserData: MockUserData
    let transport = MockTransportDelegate()

    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet {
            transport.aliceStreamContinuation = aliceStreamContinuation
        }
    }
    
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet {
            transport.bobStreamContinuation = bobStreamContinuation
        }
    }
    init() {
        self.sMockUserData = MockUserData(session: _senderSession)
        self.rMockUserData = MockUserData(session: _recipientSession)
    }
    
    func createSenderStore() -> MockIdentityStore {
        sMockUserData.identityStore(isSender: true)
    }
    
    func createRecipientStore() -> MockIdentityStore {
        rMockUserData.identityStore(isSender: false)
    }
    
    func createSenderSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt1"
        
        await _senderSession.setDatabaseDelegate(conformer: store)
        await _senderSession.setTransportDelegate(conformer: transport)
        await _senderSession.setCryptoSessionDelegate(conformer: SessionDelegate())
        
        _senderSession.isViable = true
        await _senderSession.setReceiverDelegate(conformer: ReceiverDelegate())
        transport.publishableName = sMockUserData.ssn
      _ = try await _senderSession.createSession(secretName: sMockUserData.ssn, appPassword: sMockUserData.sap) {}
        await _senderSession.setAppPassword(sMockUserData.sap)
        _ = try await _senderSession.startSession(appPassword: sMockUserData.sap)
    }
    
    func createRecipientSession(store: MockIdentityStore) async throws {
        store.localDeviceSalt = "testSalt2"
     
        await _recipientSession.setDatabaseDelegate(conformer: store)
        await _recipientSession.setTransportDelegate(conformer: transport)
        await _recipientSession.setCryptoSessionDelegate(conformer: SessionDelegate())
        
        _recipientSession.isViable = true
        await _recipientSession.setReceiverDelegate(conformer: ReceiverDelegate())
        transport.publishableName = rMockUserData.rsn
        _ = try await _recipientSession.createSession(secretName: rMockUserData.rsn, appPassword: rMockUserData.sap) {}
        await _recipientSession.setAppPassword(rMockUserData.sap)
        _ = try await _recipientSession.startSession(appPassword: rMockUserData.sap)
    }
    @Test
    func testRatchetManagerReCreation() async throws {
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        let aliceStream = AsyncStream<ReceivedMessage> { continuation in
            self.aliceStreamContinuation = continuation
        }
        
        let bobStream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }

                try await createSenderSession(store: senderStore)
        try await createRecipientSession(store: recipientStore)

                try await self._senderSession.writeTextMessage(recipient: .nickname("bob"),  text: "Message One", metadata: [:])

        Task {
            var aliceIterations = 0
            for await received in aliceStream {
                aliceIterations += 1
                try await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
                
                if aliceIterations == 2 {
                    try await self._senderSession.writeTextMessage(recipient: .nickname("bob"),  text: "Message Four", metadata: [:])
                    try await self._senderSession.writeTextMessage(recipient: .nickname("bob"),  text: "Message Five", metadata: [:])
                }
            }
        }
        
        var bobIterations = 0
        for await received in bobStream {
            bobIterations += 1
            try await self._recipientSession.receiveMessage(
                message: received.message,
                sender: received.sender,
                deviceId: received.deviceId,
                messageId: received.messageId)
            

            if bobIterations == 1 {
                try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"),  text: "Message Two", metadata: [:])
                try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"),  text: "Message Three", metadata: [:])
            }

            if bobIterations == 3 {
                aliceStreamContinuation?.finish()
                bobStreamContinuation?.finish()
            }
        }
        await _senderSession.shutdown()
        await _recipientSession.shutdown()
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

            // 2) Initialize sessions (PQXDH handshake)
            try await createSenderSession(store: senderStore)
            try await createRecipientSession(store: recipientStore)

            // 3) Kick off the very first message from Alice → Bob
            try await _senderSession.writeTextMessage(
                recipient: .nickname("bob"),
                text: "1",
                metadata: [:]
            )

            // 4) Bob’s receive‑and‑reply loop
            Task {
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
                        // Bob got all his 1 000; close his stream
                        bobStreamContinuation?.finish()
                        aliceStreamContinuation?.finish()
                    }
                }
            }

            // 5) Alice’s receive‑and‑reply loop
            var aliceReceivedCount = 0
            for await received in aliceStream {
                aliceReceivedCount += 1

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

            // 6) Cleanly shut down both sessions
            await _senderSession.shutdown()
            await _recipientSession.shutdown()
        }
    
    @Test
    func testOutOfOrderMessagesHandledCorrectly() async throws {
        let senderStore = createSenderStore()
        let recipientStore = createRecipientStore()
        
        // 1) Set up a single AsyncStream on the recipient side
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.bobStreamContinuation = continuation
        }
        
        // 2) Do the PQXDH handshake before sending any data
        try await createSenderSession(store: senderStore)
        try await createRecipientSession(store: recipientStore)
        
        // 3) Prepare 79 distinct messages
        let messages = (0..<79).map { "Out‑of‑order Message \($0)" }
        
        // 4) Send them all (in-order) from Alice → Bob
        for text in messages {
            try await _senderSession.writeTextMessage(
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
                bobStreamContinuation?.finish()
                break
            }
        }
        
        // 6) Now actually feed them into Bob’s ratchet out‑of‑order:
        //    first the very first message he should ever see…
        let first = collected.removeFirst()
        try await _recipientSession.receiveMessage(
            message: first.message,
            sender: first.sender,
            deviceId: first.deviceId,
            messageId: first.messageId)
        
        
        //    …then the rest in a random order:
        for msg in collected.shuffled() {
            try await _recipientSession.receiveMessage(
                message: msg.message,
                sender: msg.sender,
                deviceId: msg.deviceId,
                messageId: msg.messageId
            )
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

                try await createSenderSession(store: senderStore)
        try await createRecipientSession(store: recipientStore)

                try await self._senderSession.writeTextMessage(recipient: .nickname("bob"),  text: "Message One", metadata: [:])

        Task {
            var aliceIterations = 0
            for await received in aliceStream {
                aliceIterations += 1
                try await self._senderSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
                
                if aliceIterations == 2 {
                    try await self._senderSession.writeTextMessage(recipient: .nickname("bob"),  text: "Message Four", metadata: [:])
                    try await _senderSession.rotateKeysOnPotentialCompromise()
                    try await self._senderSession.writeTextMessage(recipient: .nickname("bob"),  text: "Message Five", metadata: [:])
                }
            }
        }
        
        var bobIterations = 0
        for await received in bobStream {
            bobIterations += 1
            try await self._recipientSession.receiveMessage(
                message: received.message,
                sender: received.sender,
                deviceId: received.deviceId,
                messageId: received.messageId)
            

            if bobIterations == 1 {
                try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"),  text: "Message Two", metadata: [:])
                try await _recipientSession.rotateKeysOnPotentialCompromise()
                try await self._recipientSession.writeTextMessage(recipient: .nickname("alice"),  text: "Message Three", metadata: [:])
            }

            if bobIterations == 3 {
                aliceStreamContinuation?.finish()
                bobStreamContinuation?.finish()
            }
        }
        await _senderSession.shutdown()
        await _recipientSession.shutdown()
    }
}

struct SessionDelegate: CryptoSessionDelegate {
    func communicationSynchonization(recipient: SessionModels.MessageRecipient, sharedIdentifier: String) async throws {}
    func blockUnblock(recipient: SessionModels.MessageRecipient, data: Data?, metadata: BSON.Document, myState: SessionModels.FriendshipMetadata.State) async throws {}
    func deliveryStateChanged(recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {}
    func contactCreated(recipient: SessionModels.MessageRecipient) async throws {}
    func requestMetadata(recipient: SessionModels.MessageRecipient) async throws {}
    func editMessage(recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {}
    func shouldPersist(transportInfo: Data?) -> Bool {
        true
    }
    
    func getUserInfo(_ transportInfo: Data?) async throws -> (secretName: String, deviceId: String)? {
        nil
    }
    
    func updateCryptoMessageMetadata(_ message: SessionModels.CryptoMessage, sharedMessageId: String) throws -> SessionModels.CryptoMessage {
        message
    }
    
    func updateEncryptableMessageMetadata(_ message: SessionModels.EncryptedMessage, transportInfo: Data?, identity: DoubleRatchetKit.SessionIdentity, recipient: SessionModels.MessageRecipient) async throws -> SessionModels.EncryptedMessage {
        message
    }
    
    func shouldFinishCommunicationSynchronization(_ transportInfo: Data?) -> Bool {
        false
    }
    
    func processUnpersistedMessage(_ message: SessionModels.CryptoMessage, senderSecretName: String, senderDeviceId: UUID) async throws -> Bool {
        true
    }
}

struct ReceiverDelegate: EventReceiver {
    
    func createdMessage(_ message: SessionModels.EncryptedMessage) async {
    }
    
    func updatedMessage(_ message: SessionModels.EncryptedMessage) async {
        
    }
    
    func updateContact(_ contact: SessionModels.Contact) async throws {
        
    }
    
    func contactMetadata(changed for: SessionModels.Contact) async {
        
    }
    
    func deletedMessage(_ message: SessionModels.EncryptedMessage) async {
        
    }
    
    func createdContact(_ contact: SessionModels.Contact) async throws {
        
    }
    
    func removedContact(_ secretName: String) async throws {
        
    }
    
    func synchronize(contact: SessionModels.Contact, requestFriendship: Bool) async throws {
        
    }
    
    func transportContactMetadata() async throws {
        
    }
    
    func updatedCommunication(_ model: SessionModels.BaseCommunication, members: Set<String>) async {
        
    }
}


struct ReceivedMessage {
    let message: SignedRatchetMessage
    let sender: String
    let deviceId: UUID
    let messageId: String
}

final class MockTransportDelegate: SessionTransport, @unchecked Sendable {

    struct IdentifiableSignedPublicOneTimeKey {
        let id: String
        var keys: [UserConfiguration.SignedPublicOneTimeKey]
    }
    
    struct IdentifiableSignedKyberOneTimeKey {
        let id: String
        var keys: [UserConfiguration.SignedKyberOneTimeKey]
    }
    // Properties
    var publicOneTimeKeyPairs = [IdentifiableSignedPublicOneTimeKey]()
    var kyberOneTimeKeyPairs = [IdentifiableSignedKyberOneTimeKey]()
    var publishableName: String!
    var userConfigurations = [User]()
    
    var aliceStreamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    var bobStreamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    
    // Async Methods
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> SessionModels.OneTimeKeys {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.publicSigningKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        
        // Retrieve the one-time key pair for the given secret name
        guard let oneTimeKeyPairIndex = publicOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) else {
            fatalError()
        }
        
        // Get the last key from the found one-time key pair
        let oneTimeKeyPair = publicOneTimeKeyPairs[oneTimeKeyPairIndex]
        guard let publicKey = try oneTimeKeyPair.keys.last?.verified(using: signingKey) else {
            fatalError()
        }
        
        // Remove the one-time key pair from the array
        publicOneTimeKeyPairs.remove(at: oneTimeKeyPairIndex)
        
        // Retrieve the one-time key pair for the given secret name
        guard let kyberKeyPairIndex = kyberOneTimeKeyPairs.firstIndex(where: { $0.id == secretName }) else {
            fatalError()
        }
        
        // Get the last key from the found one-time key pair
        let kyberKeyPair = kyberOneTimeKeyPairs[kyberKeyPairIndex]
        guard let kyberKey = try kyberKeyPair.keys.last?.kyberVerified(using: signingKey) else {
            fatalError()
        }
        
        // Remove the one-time key pair from the array
        kyberOneTimeKeyPairs.remove(at: kyberKeyPairIndex)
        
        return SessionModels.OneTimeKeys(curve: publicKey, kyber: kyberKey)
    }
    
    func fetchOneTimeKeyIdentites(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] {
        let config = userConfigurations.first(where: { $0.secretName == secretName })
        guard let signingKeyData = config?.config.publicSigningKey else { fatalError() }
        let signingKey = try Curve25519SigningPublicKey(rawRepresentation: signingKeyData)
        let filtered = publicOneTimeKeyPairs.filter({ $0.id == secretName })
        // Map the filtered keys to their verified IDs
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
        publicOneTimeKeyPairs.append(IdentifiableSignedPublicOneTimeKey(id: publishableName, keys: configuration.signedPublicOneTimeKeys))
        kyberOneTimeKeyPairs.append(IdentifiableSignedKyberOneTimeKey(id: publishableName, keys: configuration.signedPublicKyberOneTimeKeys))
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
    
    func receiveMessage() async throws -> String {
        ""
    }
    
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        guard let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName })?.config else {
            throw CryptoSession.SessionErrors.userNotFound
        }
        return userConfiguration
    }
    
    func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
        guard let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName })?.config else {
            throw CryptoSession.SessionErrors.configurationError
        }
        return userConfiguration
    }
    
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedPublicOneTimeKey]) async throws {
        
    }
    
    func updateOneTimeKyberKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedKyberOneTimeKey]) async throws {
        
    }
    
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {
        
    }
    
    func deleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {
        
    }

    func rotateLongTermKeys(for secretName: String,
                            deviceId: String,
                            pskData: Data,
                            signedDevice: UserConfiguration.SignedDeviceConfiguration
    ) async throws {
        guard let index = self.userConfigurations.firstIndex(where: { $0.secretName == secretName }) else {
            fatalError()
        }
        
        var userConfig = userConfigurations[index]
        
        let oldSigningKey = try Curve25519SigningPublicKey(
            rawRepresentation: userConfig.config.publicSigningKey)
        
        guard let deviceIndex = userConfig.config.signedDevices.firstIndex(where: {
            guard let verified = try? $0.verified(using: oldSigningKey) else { return false }
            return verified.deviceId.uuidString == deviceId
        }) else {
            fatalError()
        }
        
        let newSigningKey = try Curve25519SigningPublicKey(rawRepresentation: pskData)
        
        userConfig.config.signedDevices[deviceIndex] = signedDevice
        guard let verified = try signedDevice.verified(using: newSigningKey) else {
            throw CryptoSession.SessionErrors.invalidSignature
        }
        userConfig.config.publicSigningKey = verified.publicSigningKey
        userConfigurations[index] = userConfig
    }
    
    func createUploadPacket(secretName: String, deviceId: UUID, recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {
        
    }
    
    func notifyIdentityCreation(for secretName: String, keys: SessionModels.OneTimeKeys) async throws {
        
    }}

final class MockIdentityStore: CryptoSessionStore, @unchecked Sendable {
    
    var sessionContext: Data?
    func createLocalSessionContext(_ data: Data) async throws {
        sessionContext = data
    }
    
    func findLocalSessionContext() async throws -> Data {
        sessionContext!
    }
    
    func updateLocalSessionContext(_ data: Data) async throws {
        sessionContext = data
    }
    
    func deleteLocalSessionContext() async throws {
        sessionContext = nil
    }
    
    func removeContact(_ id: UUID) async throws {
        
    }
    
    func createMediaJob(_ packet: SessionModels.DataPacket) async throws {
        
    }
    
    func findAllMediaJobs() async throws -> [SessionModels.DataPacket] {
        []
    }
    
    func findMediaJob(_ id: UUID) async throws -> SessionModels.DataPacket? {
        nil
    }
    
    func deleteMediaJob(_ id: UUID) async throws {
        
    }
    
    func findLocalDeviceSalt(keyData: Data) async throws -> Data {
        keyData + "salt".data(using: .utf8)!
    }
    
    func deleteLocalDeviceSalt() async throws {
        
    }
    
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] {
        return identities
    }
    
    func updateSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {
        if let index = identities.firstIndex(where: { $0.id == session.id }) {
            identities[index] = session
        }
    }
    
    func removeSessionIdentity(_ id: UUID) async throws {
        
    }
    
    func fetchContacts() async throws -> [SessionModels.ContactModel] {
        []
    }
    
    func createContact(_ contact: SessionModels.ContactModel) async throws {
        
    }
    
    func updateContact(_ contact: SessionModels.ContactModel) async throws {
        
    }
    
    func fetchCommunications() async throws -> [SessionModels.BaseCommunication] {
        []
    }
    
    func createCommunication(_ type: SessionModels.BaseCommunication) async throws {
        
    }
    
    func updateCommunication(_ type: SessionModels.BaseCommunication) async throws {
        
    }
    
    func removeCommunication(_ type: SessionModels.BaseCommunication) async throws {
        
    }
    
    func fetchMessages(sharedCommunicationId: UUID) async throws -> [_WrappedPrivateMessage] {
        []
    }
    
    func fetchMessage(byId messageId: UUID) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
    }
    
    func fetchMessage(by sharedMessageId: String) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
    }
    
    func createMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        
    }
    
    func updateMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        
    }
    
    func removeMessage(_ message: SessionModels.EncryptedMessage) async throws {
        
    }
    
    func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>, AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>.Continuation?) {
        // Create an AsyncThrowingStream
           let stream = AsyncThrowingStream<SessionModels.EncryptedMessage, any Error> { continuation in
               
               // Simulate sending dummy messages
               for i in 1...5 {
                   if let message = try? SessionModels.EncryptedMessage(id: UUID(), communicationId: UUID(), sessionContextId: i, sharedId: "123", sequenceNumber: 1, data: Data()) {
                       
                       // Yield the message to the stream
                       continuation.yield(message)
                   }
               }
               
               // Mark the stream as finished
               continuation.finish()
           }
           
           // Return the stream and its continuation (optional)
           return (stream, nil)
    }
    
    func messageCount(for sharedIdentifier: UUID) async throws -> Int {
        1
    }
    
    func readJobs() async throws -> [SessionModels.JobModel] {
        []
    }
    
    func createJob(_ job: SessionModels.JobModel) async throws {
        
    }
    
    func updateJob(_ job: SessionModels.JobModel) async throws {
        
    }
    
    func removeJob(_ job: SessionModels.JobModel) async throws {
        
    }
    
    func findMediaJobs(for recipient: String, symmetricKey: SymmetricKey) async throws -> [SessionModels.DataPacket] {
        []
    }
    
    func findMediaJob(for synchronizationIdentifier: String, symmetricKey: SymmetricKey) async throws -> SessionModels.DataPacket? {
        nil
    }
    
    
    var identities = [SessionIdentity]()
    let crypto = NeedleTailCrypto()
    var mockUserData: MockUserData
    let session: CryptoSession
    let isSender: Bool
    init(mockUserData: MockUserData, session: CryptoSession, isSender: Bool) {
        self.mockUserData = mockUserData
        self.session = session
        self.isSender = isSender
    }
    
    
    func createSessionIdentity(_ session: SessionIdentity) async throws {
        identities.append(session)
    }
 
    
    var localDeviceSalt: String?
    
    func findLocalDeviceSalt() async throws -> String {
        guard let salt = localDeviceSalt else {
            throw CryptoSession.SessionErrors.saltError
        }
        return salt
    }
    
    func findLocalDeviceConfiguration() async throws -> Data {
        return encyrptedConfigurationForTesting
    }
    
    var encyrptedConfigurationForTesting = Data()
    func createLocalDeviceConfiguration(_ configuration: Data) async throws {
        encyrptedConfigurationForTesting = configuration
    }
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
    
    let session: CryptoSession
    init(session: CryptoSession) {
        self.session = session
    }
    
    func identityStore(isSender: Bool) -> MockIdentityStore {
        return MockIdentityStore(mockUserData: self, session: session, isSender: isSender)
    }
    
}

extension Data {
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}


struct User {
    let secretName: String
    let deviceId: UUID
    var config: UserConfiguration
}
