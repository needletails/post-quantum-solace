//
//  EndToEndTests.swift
//  needletail-crypto
//
//  Created by Cole M on 9/19/24.
//
@testable import CryptoSession
@preconcurrency import CryptoKit
import BSON
import Testing
import Foundation
import NeedleTailAsyncSequence
import NeedleTailCrypto
import DoubleRatchetKit

class EndToEndTests {
    
    let processor = JobProcessor()
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
        store.localDeviceSalt = "testSalt"
        await _session.setDatabaseDelegate(conformer: store)
        await _session.setTransportDelegate(conformer: transport)
        
        _session.isViable = true
        await _session.setReceiverDelegate(conformer: ReceiverDelegate())
        let session = try! await _session.createSession(secretName: mockUserData.ssn, appPassword: mockUserData.sap)
        mockUserData.senderPublicIdentity = await session.sessionContext?.sessionUser.deviceIdentity
        return session
    }
    
    func recipentSession() async throws -> CryptoSession {
        let store = mockUserData.identityStore(isSender: false)
        store.localDeviceSalt = "testSalt"
        await _session.setDatabaseDelegate(conformer: store)
        await _session.setTransportDelegate(conformer: transport)
        
        _session.isViable = true
        await _session.setReceiverDelegate(conformer: ReceiverDelegate())
        let session = try! await _session.createSession(secretName: mockUserData.rsn, appPassword: mockUserData.sap)
        //            mockUserData.receiverPublicIdentity = await session.sessionContext?.sessionUser.deviceIdentity
        return session
    }
    
    @Test
    func testWriteAndStreamMessage() async throws {
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.streamContinuation = continuation
        }
        
        let privateSigningKey = MockUserData.getPrivateSigningKey()
        let privateKey = MockUserData.getPrivateKey()
        let senderSession = try await senderSession()
        
        let keys1 = await DeviceKeys(
            deviceIdentity: senderSession.sessionContext!.sessionUser.deviceKeys.deviceIdentity,
            privateSigningKey: privateSigningKey!.rawRepresentation,
            privateKey: privateKey!.rawRepresentation)
        
        let user1 = await SessionUser(
            secretName: senderSession.sessionContext!.sessionUser.secretName,
            deviceIdentity: senderSession.sessionContext!.sessionUser.deviceIdentity,
            deviceKeys: keys1)
        
        let context1 = await SessionContext(
            sessionUser: user1,
            databaseEncryptionKey: senderSession.sessionContext!.databaseEncryptionKey,
            sessionContextId: senderSession.sessionContext!.sessionContextId,
            lastUserConfiguration: senderSession.sessionContext!.lastUserConfiguration,
            registrationState: senderSession.sessionContext!.registrationState)
        await senderSession.setSessionContext(context1)
        
        //        OUT
        await #expect(throws: Never.self, performing: {
            try await senderSession.writeTextMessage(
                messageType: .text,
                messageFlags: .none,
                recipient: .nickname("secretName2"),
                text: "Some Message",
                metadata: [:],
                pushType: .message)
        })
        
        let recipentSession = try await recipentSession()
        let keys = DeviceKeys(
            deviceIdentity: mockUserData.receiverPublicIdentity,
            privateSigningKey: privateSigningKey!.rawRepresentation,
            privateKey: privateKey!.rawRepresentation)
        
        let user = await SessionUser(
            secretName:  recipentSession.sessionContext!.sessionUser.secretName,
            deviceIdentity: mockUserData.receiverPublicIdentity,
            deviceKeys: keys)
        
        let context = await SessionContext(
            sessionUser: user,
            databaseEncryptionKey: recipentSession.sessionContext!.databaseEncryptionKey,
            sessionContextId: recipentSession.sessionContext!.sessionContextId,
            lastUserConfiguration: recipentSession.sessionContext!.lastUserConfiguration,
            registrationState: recipentSession.sessionContext!.registrationState)
        await recipentSession.setSessionContext(context)
        
        //        IN
        for await received in stream {
            await #expect(throws: Never.self, performing: {
                try await recipentSession.receiveMessage(
                    message: received.message,
                    sender: received.sender,
                    deviceIdentity: received.deviceIdentity,
                    messageId: received.messageId)
            })
            return
        }
    }
    
    @Test
    func testBatchWriteAndStreamMessage() async throws {
        
        let stream = AsyncStream<ReceivedMessage> { continuation in
            self.streamContinuation = continuation
        }
        
        let privateSigningKey = MockUserData.getPrivateSigningKey()
        let privateKey = MockUserData.getPrivateKey()
        let senderSession = try await senderSession()
        
        let keys1 = await DeviceKeys(
            deviceIdentity: senderSession.sessionContext!.sessionUser.deviceKeys.deviceIdentity,
            privateSigningKey: privateSigningKey!.rawRepresentation,
            privateKey: privateKey!.rawRepresentation)
        
        let user1 = await SessionUser(
            secretName: senderSession.sessionContext!.sessionUser.secretName,
            deviceIdentity: senderSession.sessionContext!.sessionUser.deviceIdentity,
            deviceKeys: keys1)
        
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
                    try await senderSession.writeTextMessage(
                        messageType: .text,
                        messageFlags: .none,
                        recipient: .nickname("secretName2"),
                        text: message,
                        metadata: [:],
                        pushType: .message)
                case .consumed:
                    break
                }
            }
        })
        
        
        let recipentSession = try await recipentSession()
        let keys = DeviceKeys(
            deviceIdentity: mockUserData.receiverPublicIdentity,
            privateSigningKey: privateSigningKey!.rawRepresentation,
            privateKey: privateKey!.rawRepresentation)
        
        let user = await SessionUser(
            secretName:  recipentSession.sessionContext!.sessionUser.secretName,
            deviceIdentity: mockUserData.receiverPublicIdentity,
            deviceKeys: keys)
        
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
                    deviceIdentity: received.deviceIdentity,
                    messageId: received.messageId)
            })
            
            if iterations == 10 {
                return
            }
        }
        
    }
}


struct ReceiverDelegate: NTMessageReceiver {
    func createdMessage(_ message: MessageModel) async {
        await print("Created message: \(String(describing: message.props?.sendersIdentity))")
    }
    
    func updatedMessage(_ message: MessageModel) async {
        print("Updated message: \(message)")
    }
    
    func createContact(_ contact: Contact) async {
        print("Created contact: \(contact)")
    }
    
    func contactMetadata(changed for: Contact) async {
        print("Contact metadata changed: \(`for`)")
    }
}


struct ReceivedMessage {
    let message: SignedRatchetMessage
    let sender: String
    let deviceIdentity: UUID
    let messageId: String
}

// Mock implementations of the required protocols
final class MockTransportDelegate: SessionTransport, @unchecked Sendable {
    
    var streamContinuation: AsyncStream<ReceivedMessage>.Continuation?
    
    
    func sendMessage(_ message: SignedRatchetMessage, to secretName: String, with deviceIdentity: UUID, pushType: PushNotificationType, remoteId: String) async throws {
        let received = ReceivedMessage(message: message, sender: secretName, deviceIdentity: deviceIdentity, messageId: remoteId)
        streamContinuation!.yield(received)
    }
    
    func receiveMessage() async throws -> String {
        ""
    }
    enum MockTransportError: Error {
        case noConfig
    }
    func findConfiguration(for secretName: String) async throws -> UserConfiguration {
        guard let userConfiguration = userConfiguration else { throw MockTransportError.noConfig }
        return userConfiguration
    }
    
    func publishUser(configuration: UserConfiguration) async throws {
        self.userConfiguration = configuration
    }
    
    func publishAuxillary(configuration: UserDeviceConfiguration) async throws {
        
    }
    
    var shouldReturnConfiguration: Bool = true
    var userConfiguration: UserConfiguration?
    
    func findUserConfiguration() async throws -> UserConfiguration {
        if userConfiguration == nil {
            throw CryptoSession.SessionErrors.configurationError
        } else {
            return userConfiguration.unsafelyUnwrapped
        }
    }
}

final class MockIdentityStore: CryptoSessionStore, @unchecked Sendable {
    var identities = [SessionIdentityModel]()
    let crypto = NeedleTailCrypto()
    var mockUserData: MockUserData
    let session: CryptoSession
    let isSender: Bool
    init(mockUserData: MockUserData, session: CryptoSession, isSender: Bool) {
        self.mockUserData = mockUserData
        self.session = session
        self.isSender = isSender
    }
    
    func updateLocalDeviceConfiguration(_ data: Data) async throws {
        
    }
    
    func deleteLocalDeviceConfiguration() async throws {
        
    }
    
    func createSessionIdentity(_ session: SessionIdentityModel) async throws {
        identities.append(session)
    }
    
    func fetchSessionIdentities() async throws -> [SessionIdentityModel] {
        let privateSigningKey = MockUserData.getPrivateSigningKey()
        let privateKey = MockUserData.getPrivateKey()
        if identities.isEmpty, await identities.first?.props?.publicSigningRepresentable != privateSigningKey?.publicKey.rawRepresentation {
            guard let passwordData = "123".data(using: .utf8) else {
                fatalError()
            }
            guard let saltData = localDeviceSalt!.data(using: .utf8) else {
                fatalError()
            }
            
            let symmetricKey = await crypto.deriveStrictSymmetricKey(data: passwordData, salt: saltData)
            
         
            let props = SessionIdentityModel.Props(
                secretName: isSender ? mockUserData.rsn : mockUserData.ssn,
                deviceIdentity: isSender ? mockUserData.receiverPublicIdentity : mockUserData.senderPublicIdentity!,
                senderIdentity: mockUserData.sci,
                publicKeyRepesentable: privateKey!.publicKey.rawRepresentation,
                publicSigningRepresentable: privateSigningKey!.publicKey.rawRepresentation,
                deviceName: mockUserData.dn)
            let identity = try SessionIdentityModel(
                props: props,
                symmetricKey: symmetricKey)
            identities.append(identity)
        }
        return identities
    }
    
    func updateSessionIdentity(_ session: SessionIdentityModel) async throws {
        
    }
    
    func removeSessionIdentity(_ session: SessionIdentityModel) async throws {
        
    }
    
    func fetchContacts() async throws -> [ContactModel] {
        []
    }
    
    func createContact(_ contact: ContactModel) async throws {
        
    }
    
    func updateContact(_ contact: ContactModel) async throws {
        
    }
    
    func removeContact(_ contact: ContactModel) async throws {
        
    }
    
    func fetchCommunicationTypes() async throws -> [CommunicationModel] {
        []
    }
    
    func createCommunicationType(_ type: CommunicationModel) async throws {
        
    }
    
    func updateCommunicationType(_ type: CommunicationModel) async throws {
        
    }
    
    func removeCommunicationType(_ type: CommunicationModel) async throws {
        
    }
    
    func fetchMessage(byId messageId: UUID) async throws -> MessageModel {
        return mockMessageModel
    }
    
    func fetchMessage(by sharedMessageId: String) async throws -> MessageModel {
        return mockMessageModel
    }
    
    func createMessage(_ message: MessageModel) async throws {
        
    }
    
    func updateMessage(_ message: MessageModel) async throws {
        
    }
    
    func removeMessage(_ message: MessageModel) async throws {
        
    }
    
    func listMessages(in communication: UUID, senderId: Int, minimumOrder: Int?, maximumOrder: Int?, offsetBy: Int, limit: Int) async throws -> [MessageModel] {
        []
    }
    
    func readJobs() async throws -> [JobModel] {
        []
    }
    
    func createJob(_ job: JobModel) async throws {
        
    }
    
    func updateJob(_ job: JobModel) async throws {
        
    }
    
    func removeJob(_ job: JobModel) async throws {
        
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
    var mockMessageModel: MessageModel!
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
        messageType: .text,
        messageFlags: .none,
        recipient: .nickname("secretName2"),
        text: "Some Message",
        pushType: .message,
        metadata: [:],
        sentDate: Date(),
        destructionDate: nil)
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
