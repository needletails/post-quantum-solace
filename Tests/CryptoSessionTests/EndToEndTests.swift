//
//  EndToEndTests.swift
//  needletail-crypto
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

class EndToEndTests: @unchecked Sendable {
    
    let crypto = NeedleTailCrypto()
    var _session = CryptoSession.shared
    var mockUserData: MockUserData
    let transport = MockTransportDelegate()
    var streamContinuation: AsyncStream<ReceivedMessage>.Continuation? {
        didSet {
            transport.streamContinuation = streamContinuation
        }
    }
    init() {
        self.mockUserData = MockUserData(session: _session)
    
    }
    
    func senderSession() async throws -> CryptoSession {
        let store = mockUserData.identityStore(isSender: true)
        store.localDeviceSalt = "testSalt1"
        await _session.setDatabaseDelegate(conformer: store)
        await _session.setTransportDelegate(conformer: transport)
        await _session.setCryptoSessionDelegate(conformer: SessionDelegate())
        
        _session.isViable = true
        await _session.setReceiverDelegate(conformer: ReceiverDelegate())
        let session = try! await _session.createSession(secretName: mockUserData.ssn, appPassword: mockUserData.sap) {
            
        }
        let config = try await session.sessionContext!.lastUserConfiguration.getVerifiedDevices().last!
        let identity = try await session.createEncryptableSessionIdentityModel(
            with: config,
            for: session.sessionContext!.sessionUser.secretName,
            associatedWith: session.sessionContext!.sessionUser.deviceId,
            new: Int.random(in: 0...100))
        
        try await transport.publishUserConfiguration(session.sessionContext!.lastUserConfiguration, updateKeyBundle: false)
        try await store.createSessionIdentity(identity)
        
        mockUserData.senderPublicIdentity = await session.sessionContext?.sessionUser.deviceId
        return session
    }
    
    func recipentSession() async throws -> CryptoSession {
        let store = mockUserData.identityStore(isSender: false)
        store.localDeviceSalt = "testSalt2"
     
        await _session.setDatabaseDelegate(conformer: store)
        await _session.setTransportDelegate(conformer: transport)
        await _session.setCryptoSessionDelegate(conformer: SessionDelegate())
        
        _session.isViable = true
        await _session.setReceiverDelegate(conformer: ReceiverDelegate())
        let session = try! await _session.createSession(secretName: mockUserData.rsn, appPassword: mockUserData.sap) {
           //Create Transport
          
        }
        return session
    }
    
    @Test
    func testWriteAndStreamMessage() async throws {
        
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.streamContinuation = continuation
        }
        let senderSession = try await senderSession()
        let recipentSession = try await recipentSession()
        
        //        OUT
        await #expect(throws: Never.self, performing: {
            let writeClock = ContinuousClock()
            let duration = try await writeClock.measure {
                try await senderSession.writeTextMessage(recipient: .nickname("secretname1"),  text: "Some Message", metadata: [:])
            }
            print("WRITE TOOK", duration.components.seconds)
        })
        
        //        IN
        for await received in stream {
            await #expect(throws: Never.self, performing: {
                let readClock = ContinuousClock()
                let duration = try await readClock.measure {
                    try await recipentSession.receiveMessage(
                        message: received.message,
                        sender: received.sender,
                        deviceId: received.deviceId,
                        messageId: received.messageId)
                }
                                print("READ TOOK", duration.components.seconds)
                })
            return
        }
    }
    
    @Test
    func testBatchWriteAndStreamMessage() async throws {
        
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.streamContinuation = continuation
        }
        
        // Generate 100 private one-time key pairs
        let privateOneTimeKeyPairs: [CryptoSession.KeyPair] = try (0..<100).map { _ in
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let privateKeyRep = try Curve25519PrivateKeyRepresentable(id: id, privateKey.rawRepresentation)
            let publicKey = try Curve25519PublicKeyRepresentable(id: id, privateKey.publicKey.rawRepresentation)
            return CryptoSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }
        
        let privateSigningKey = MockUserData.getPrivateSigningKey()
        let privateKey = MockUserData.getPrivateKey()
        let kyber1024PrivateKey = try crypto.generateKyber1024PrivateSigningKey()
        let senderSession = try await senderSession()
        
        
        let keys1 = await DeviceKeys(
            deviceId: senderSession.sessionContext!.sessionUser.deviceKeys.deviceId,
            privateSigningKey: privateSigningKey!.rawRepresentation,
            privateLongTermKey: privateKey!.rawRepresentation,
            privateOneTimeKeys: privateOneTimeKeyPairs.map { $0.privateKey },
            kyber1024PrivateKey: kyber1024PrivateKey.encode())
        
        let user1 = await SessionUser(
            secretName: senderSession.sessionContext!.sessionUser.secretName,
            deviceId: senderSession.sessionContext!.sessionUser.deviceId,
            deviceKeys: keys1,
            metadata: .init())
        
        let context1 = await SessionContext(
            sessionUser: user1,
            databaseEncryptionKey: senderSession.sessionContext!.databaseEncryptionKey,
            sessionContextId: senderSession.sessionContext!.sessionContextId,
            lastUserConfiguration: senderSession.sessionContext!.lastUserConfiguration,
            registrationState: senderSession.sessionContext!.registrationState)
        await senderSession.setSessionContext(context1)
        var iterations = 0
        
        let consumer = NeedleTailAsyncConsumer<String>()
        for _ in 0..<10 {
            await consumer.feedConsumer("Some Message")
        }
        await #expect(throws: Never.self, performing: {
            for try await result in NeedleTailAsyncSequence(consumer: consumer) {
                switch result {
                case .success(let message):
                    try await senderSession.writeTextMessage(recipient: .nickname("secretName2"),  text: message, metadata: [:])
                case .consumed:
                    break
                }
            }
        })
        
        
        let recipentSession = try await recipentSession()
        let keys = DeviceKeys(
            deviceId: mockUserData.receiverPublicIdentity,
            privateSigningKey: privateSigningKey!.rawRepresentation,
            privateLongTermKey: privateKey!.rawRepresentation,
            privateOneTimeKeys: privateOneTimeKeyPairs.map { $0.privateKey },
            kyber1024PrivateKey: kyber1024PrivateKey.encode())
        
        let user = await SessionUser(
            secretName:  recipentSession.sessionContext!.sessionUser.secretName,
            deviceId: mockUserData.receiverPublicIdentity,
            deviceKeys: keys,
            metadata: .init())
        
        let context = await SessionContext(
            sessionUser: user,
            databaseEncryptionKey: recipentSession.sessionContext!.databaseEncryptionKey,
            sessionContextId: recipentSession.sessionContext!.sessionContextId,
            lastUserConfiguration: recipentSession.sessionContext!.lastUserConfiguration,
            registrationState: recipentSession.sessionContext!.registrationState)
        await recipentSession.setSessionContext(context)
        
        
        for await received in stream {
            iterations += 1
            await #expect(throws: Never.self, performing: {
                try await recipentSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceId: received.deviceId,
                    messageId: received.messageId)
            })
            
            if iterations == 10 {
                return
            }
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
    let crypto = NeedleTailCrypto()
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, updateKeyBundle: Bool) async throws {
        self.userConfigurations.append(.init(secretName: "secretname1", config: configuration))
    }
    
    func fetchOneTimeKey(for secretName: String, deviceId: String) async throws -> DoubleRatchetKit.Curve25519PublicKeyRepresentable {
        try DoubleRatchetKit.Curve25519PublicKeyRepresentable(crypto.generateCurve25519PrivateKey().publicKey.rawRepresentation)
    }
    
    func updateOneTimeKeys(for secretName: String) async throws {
        
    }
    
    func deleteOneTimeKey(for secretName: String, with id: String) async throws {
        
    }
    
    func createUploadPacket(secretName: String, deviceId: UUID, recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {
        
    }
    
    
    
    var streamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    
    
    func sendMessage(_
                     message: SignedRatchetMessage,
                     metadata: SignedRatchetMessageMetadata) async throws {
        let received = ReceivedMessage(message: message, sender: metadata.secretName, deviceId: metadata.deviceId, messageId: metadata.sharedMessageIdentifier)
        streamContinuation!.yield(received)
    }
    
    func receiveMessage() async throws -> String {
        ""
    }
    enum MockTransportError: Error {
        case noConfig
    }
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {

        guard let userConfiguration =  userConfigurations.first(where: { $0.secretName == secretName })?.config else {
            throw CryptoSession.SessionErrors.userNotFound
        }
        print(secretName)
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
    func createLocalSessionContext(_ data: Data) async throws {
        
    }
    
    func findLocalSessionContext() async throws -> Data {
        Data()
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
        Data()
    }
    
    func deleteLocalDeviceSalt() async throws {
        
    }
    
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] {
        identities
    }
    
    func updateSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {
        
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
    let config: UserConfiguration
}
