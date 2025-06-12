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
    var streamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet {
            transport.streamContinuation = streamContinuation
        }
    }
    init() {
        self.sMockUserData = MockUserData(session: _senderSession)
        self.rMockUserData = MockUserData(session: _recipientSession)
    }
    
    func senderSession() async throws {
        let store = sMockUserData.identityStore(isSender: true)
        store.localDeviceSalt = "testSalt1"
        
        await _senderSession.setDatabaseDelegate(conformer: store)
        await _senderSession.setTransportDelegate(conformer: transport)
        await _senderSession.setCryptoSessionDelegate(conformer: SessionDelegate())
        
        _senderSession.isViable = true
        await _senderSession.setReceiverDelegate(conformer: ReceiverDelegate())
        transport.publishableName = sMockUserData.ssn
      _ = try! await _senderSession.createSession(secretName: sMockUserData.ssn, appPassword: sMockUserData.sap) {}
    }
    
    func recipentSession() async throws {
        let store = rMockUserData.identityStore(isSender: false)
        store.localDeviceSalt = "testSalt2"
     
        await _recipientSession.setDatabaseDelegate(conformer: store)
        await _recipientSession.setTransportDelegate(conformer: transport)
        await _recipientSession.setCryptoSessionDelegate(conformer: SessionDelegate())
        
        _recipientSession.isViable = true
        await _recipientSession.setReceiverDelegate(conformer: ReceiverDelegate())
        transport.publishableName = rMockUserData.rsn
        _ = try! await _recipientSession.createSession(secretName: rMockUserData.rsn, appPassword: rMockUserData.sap) {
           //Create Transport
          
        }
    }

    @Test
    func testBatchWriteAndStreamMessage() async throws {
        
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.streamContinuation = continuation
        }
        
        try await Task { [weak self] in
            guard let self else { return }
            try await senderSession()
            try await recipentSession()
        }.value
        
        var iterations = 0
        
        let consumer = NeedleTailAsyncConsumer<String>()
        for i in 0..<10_000 {
            await consumer.feedConsumer("Some Message \(i)")
        }
        
        for try await result in NeedleTailAsyncSequence(consumer: consumer) {
            switch result {
            case .success(let message):
                try await self._senderSession.writeTextMessage(recipient: .nickname("secretName2"),  text: message, metadata: [:])
            case .consumed:
                break
            }
        }
        
        for await received in stream {
            iterations += 1
            try await self._recipientSession.receiveMessage(
                message: received.message,
                sender: received.sender,
                deviceId: received.deviceId,
                messageId: received.messageId)
            
            if iterations == 10_000 {
                return
            }
        }
    }
    
    @Test
    func testOutOfOrderMessagesHandledCorrectly() async throws {
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.streamContinuation = continuation
        }

        try await Task { [weak self] in
            guard let self else { return }
            try await senderSession()
            try await recipentSession()
        }.value

        let consumer = NeedleTailAsyncConsumer<String>()
        let messages = (0..<79)
            .map { "Out-of-order Message \($0)" }

        for message in messages {
            await consumer.feedConsumer(message)
        }

        // Send messages (in original order)
        for message in messages {
            try await self._senderSession.writeTextMessage(
                recipient: .nickname("secretName2"),
                text: message,
                metadata: [:])
        }

        var iterations = 0

        var receivedMessages: [ReceivedMessage] = []
        for await received in stream {
            iterations += 1
            receivedMessages.append(received)
            if iterations == 79 {
                break
            }
        }
        
        let firstMessage = receivedMessages.removeFirst()
        try await self._recipientSession.receiveMessage(
            message: firstMessage.message,
            sender: firstMessage.sender,
            deviceId: firstMessage.deviceId,
            messageId: firstMessage.messageId)
    
        for message in receivedMessages.shuffled() {
            try await self._recipientSession.receiveMessage(
                message: message.message,
                sender: message.sender,
                deviceId: message.deviceId,
                messageId: message.messageId)
        }
    }
    
}

struct SessionDelegate: CryptoSessionDelegate {
    func communicationSynchonization(recipient: SessionModels.MessageRecipient, sharedIdentifier: String) async throws {
        
    }
    
    func blockUnblock(recipient: SessionModels.MessageRecipient, data: Data?, metadata: BSON.Document, myState: SessionModels.FriendshipMetadata.State) async throws {
        
    }
    
    func deliveryStateChanged(recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {
        
    }
    
    func contactCreated(recipient: SessionModels.MessageRecipient) async throws {
        
    }
    
    func requestMetadata(recipient: SessionModels.MessageRecipient) async throws {
        
    }
    
    func editMessage(recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {
        
    }
    
    func shouldPersist(transportInfo: Data?) -> Bool {
        true
    }
    
    func getUserInfo(_ transportInfo: Data?) async throws -> (secretName: String, deviceId: String)? {
        ("", "")
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

// Mock implementations of the required protocols
final class MockTransportDelegate: SessionTransport, @unchecked Sendable {
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {
        
    }
    
    func notifyIdentityCreation(for secretName: String, keys: SessionModels.OneTimeKeys) async throws {
        
    }
    
    
  
    // Generate 100 private one-time key pairs
    let privateOneTimeKeyPairs: [CryptoSession.KeyPair<Curve25519PublicKeyRepresentable, Curve25519PrivateKeyRepresentable>]
    let kyberOneTimeKeyPairs: [CryptoSession.KeyPair<Kyber1024PublicKeyRepresentable,Kyber1024PrivateKeyRepresentable>]
    
    init() {
        privateOneTimeKeyPairs = try! (0..<100).map { _ in
            let crypto = NeedleTailCrypto()
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let privateKeyRep = try Curve25519PrivateKeyRepresentable(id: id, privateKey.rawRepresentation)
            let publicKey = try Curve25519PublicKeyRepresentable(id: id, privateKey.publicKey.rawRepresentation)
            return CryptoSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }
        
        kyberOneTimeKeyPairs = try! (0..<100).map { _ in
            let crypto = NeedleTailCrypto()
            let id = UUID()
            let privateKey = try crypto.generateKyber1024PrivateSigningKey()
            let privateKeyRep = try Kyber1024PrivateKeyRepresentable(id: id, privateKey.encode())
            let publicKey = try Kyber1024PublicKeyRepresentable(id: id, privateKey.publicKey.rawRepresentation)
            return CryptoSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }
    }
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> SessionModels.OneTimeKeys {
        guard let privateKey = privateOneTimeKeyPairs.last else { fatalError() }
        guard let privateKyberKey = kyberOneTimeKeyPairs.last else { fatalError() }
        return SessionModels.OneTimeKeys(curve: privateKey.publicKey, kyber: privateKyberKey.publicKey)
    }
    
    func fetchOneTimeKeyIdentites(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] {
        privateOneTimeKeyPairs.map { $0.publicKey.id }
    }
    
    func updateOneTimeKyberKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedKyberOneTimeKey]) async throws {
        
    }
    
    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {
        
    }
    
    func rotateLongTermKeys(for secretName: String, deviceId: String, keys: SessionModels.LongTermKeys) async throws {
        
    }
    
    func fetchOneTimeKey(for secretName: String, deviceId: String, senderSecretName: String, sender keyId: String) async throws -> DoubleRatchetKit.Curve25519PublicKeyRepresentable {
        try .init(Data())
    }
    
    func deleteOneTimeKeys(for secretName: String, with id: String) async throws {
        
    }
    
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient identity: UUID) async throws {
        self.userConfigurations.append(.init(secretName: publishableName, deviceId: identity, config: configuration))
    }
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> [UUID] {
        []
    }
    
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedPublicOneTimeKey]) async throws {
        
    }
    var publishableName: String!
    
    let crypto = NeedleTailCrypto()
    
    func updateOneTimeKeys(for secretName: String) async throws {
        
    }
    
    func createUploadPacket(secretName: String, deviceId: UUID, recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {
        
    }

    var streamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    
    
    func sendMessage(_
                     message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws {
        guard let sender = userConfigurations.first(where: { $0.secretName != metadata.secretName }) else { return }
        let received = ReceivedMessage(message: message, sender: sender.secretName, deviceId: sender.deviceId, messageId: metadata.sharedMessageIdentifier)
        streamContinuation!.yield(received)
    }
    
    func receiveMessage() async throws -> String {
        ""
    }
    enum MockTransportError: Error {
        case noConfig
    }
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        guard let userConfiguration = userConfigurations.first(where: { $0.secretName == secretName })?.config else {
            throw CryptoSession.SessionErrors.userNotFound
        }
        return userConfiguration
    }

    var shouldReturnConfiguration: Bool = true
    var userConfigurations = [User]()
    
    func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
        if userConfigurations.isEmpty {
            throw CryptoSession.SessionErrors.configurationError
        } else {
            return userConfigurations.first(where: { $0.secretName == secretName })!.config
        }
    }
}

final class MockIdentityStore: CryptoSessionStore, @unchecked Sendable {
    
    var sessionContext: Data?
    func createLocalSessionContext(_ data: Data) async throws {
        sessionContext = data
    }
    
    func findLocalSessionContext() async throws -> Data {
        sessionContext!
    }
    
    func updateLocalSessionContext(_ data: Data) async throws {
        
    }
    
    func deleteLocalSessionContext() async throws {
        
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
        identities
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
    
    
    // Static property to hold the private signing key
    private nonisolated(unsafe) static var privateSigningKey: Curve25519SigningPrivateKey?

        // Static method to get the private signing key
        static func getPrivateSigningKey() -> Curve25519SigningPrivateKey? {
            // Check if the key is already initialized
            if privateSigningKey == nil {
                print("Initializing private signing key...")
                privateSigningKey = Curve25519SigningPrivateKey()
                print("Initialized private signing key:", privateSigningKey?.publicKey.rawRepresentation.hexString ?? "none")
            } else {
                print("Returning existing private signing key...")
            }
            return privateSigningKey
        }
    
    private nonisolated(unsafe) static var privateKey: Curve25519PrivateKey?

        // Static method to get the private signing key
        static func getPrivateKey() -> Curve25519PrivateKey? {
            // Check if the key is already initialized
            if privateKey == nil {
                print("Initializing private key...")
                privateKey = Curve25519PrivateKey()
                print("Initialized private key:", privateKey?.publicKey.rawRepresentation.hexString ?? "none")
            } else {
                print("Returning existing private key...")
            }
            return privateKey
        }
    
    
    var senderPublicIdentity: UUID?
    let ssn = "secretName1"
    let sap = "123"
    var receiverPublicIdentity = UUID()
    let sci = 0
    let dn = "deviceName"
    let rsn = "secretName2"
    let lid = UUID()
    let ntm = CryptoMessage(
        text: "Some Message",
        metadata: [:],
        recipient: .nickname("secretName2"),
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
    let config: UserConfiguration
}
