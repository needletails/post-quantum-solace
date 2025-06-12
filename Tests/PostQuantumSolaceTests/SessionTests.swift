//
//  SessionTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 5/10/25.
//
import Foundation
import Testing
import BSON
import NeedleTailCrypto
import Crypto
import SessionModels
import SessionEvents
import DoubleRatchetKit
@testable import CryptoSession

actor SessionTests {
    
    let session = CryptoSession.shared
    let crypto = NeedleTailCrypto()
    
    
    let remoteKeyIds: [UUID] = []
    
    struct KeyPair {
        let id: UUID
        let publicKey: Curve25519PublicKeyRepresentable
        let privateKey: Curve25519PrivateKeyRepresentable
    }
    
    private var senderCachedKeyPairs: [KeyPair]?
    private var badCachedKeyPairs: [KeyPair]?
    
    func senderOneTimeKeys() throws -> [KeyPair] {
        if let cached = senderCachedKeyPairs { return cached }
        let batch = try generateBatch()
        senderCachedKeyPairs = batch
        return batch
    }
    
    func badOneTimeKeys() throws -> [KeyPair] {
        if let cached = badCachedKeyPairs { return cached }
        let batch = try generateBatch()
        badCachedKeyPairs = batch
        return batch
    }
    
    private func generateBatch() throws -> [KeyPair] {
        try (0..<100).map { _ in
            let id = UUID()
            let priv = crypto.generateCurve25519PrivateKey()
            return KeyPair(
                id: id,
                publicKey: try .init(id: id, priv.publicKey.rawRepresentation),
                privateKey: try .init(id: id, priv.rawRepresentation)
            )
        }
    }

    @Test
    func testLocalKeySynchronization() async throws {
        let store = MockIdentityStore(
            mockUserData: .init(session: session),
            session: session,
            isSender: false)

        let did = UUID()
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)

        // Generate 100 valid sender keys
        let validKeys = try senderOneTimeKeys()
        let badKeys = try badOneTimeKeys()

        let signedPublicOneTimeKeys: [UserConfiguration.SignedPublicOneTimeKey] = try validKeys.map {
            try UserConfiguration.SignedPublicOneTimeKey(
                key: $0.publicKey,
                deviceId: did,
                signingKey: senderspk)
        }
        
        let kyberOneTimeKeyPairs: [CryptoSession.KeyPair] = try (0..<100).map { _ in
            let id = UUID()
            let privateKey = try crypto.generateKyber1024PrivateSigningKey()
            let privateKeyRep = try Kyber1024PrivateKeyRepresentable(id: id, privateKey.encode())
            let publicKey = try Kyber1024PublicKeyRepresentable(id: id, privateKey.publicKey.rawRepresentation)
            return CryptoSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }
        let finalKyber1024Key =  try crypto.generateKyber1024PrivateSigningKey()

        let sessionUser = SessionUser(
            secretName: "user1",
            deviceId: did,
            deviceKeys: .init(
                deviceId: did,
                privateSigningKey: senderspk.rawRepresentation,
                privateLongTermKey: senderltpk.rawRepresentation,
                privateOneTimeKeys: validKeys.map(\.privateKey),
                privateKyberOneTimeKeys: kyberOneTimeKeyPairs.map { $0.privateKey },
                finalKyberPrivateKey: try .init(finalKyber1024Key.encode())),
            metadata: .init())

        let signedPublicKyberOneTimeKeys: [UserConfiguration.SignedKyberOneTimeKey] = try kyberOneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedKyberOneTimeKey(
                key: keyPair.publicKey,
                deviceId: did,
                signingKey: senderspk)
        }
        
        let context = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: senderDBSK.withUnsafeBytes({ Data($0) }),
            sessionContextId: 123,
            lastUserConfiguration: .init(
                publicSigningKey: senderspk.publicKey.rawRepresentation,
                signedDevices: [],
                signedPublicOneTimeKeys: signedPublicOneTimeKeys,
                signedPublicKyberOneTimeKeys: signedPublicKyberOneTimeKeys),
            registrationState: .registered)

        await session.setAppPassword("123")
        let passwordData = await session.appPassword.data(using: .utf8)!
        let saltData = try await store.findLocalDeviceSalt(keyData: passwordData)
        let symmetricKey = await crypto.deriveStrictSymmetricKey(data: passwordData, salt: saltData)

        let data = try BSONEncoder().encodeData(context)
        let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey)
        try await store.createLocalSessionContext(encryptedData!)
        await session.setDatabaseDelegate(conformer: store)

        // ✅ First Test Case: Remote list has *some* valid keys
        let partialKeys = Array(validKeys.prefix(10)).map(\.id)
        _ = try await session.synchronizeLocalKeys(cache: session.cache!, keys: partialKeys, type: .curve)

        
        let updatedData = try await store.findLocalSessionContext()
        let decrypted = try crypto.decrypt(data: updatedData, symmetricKey: symmetricKey)
        let decoded = try BSONDecoder().decode(SessionContext.self, from: Document(data: decrypted!))
        #expect(decoded.sessionUser.deviceKeys.privateOneTimeKeys.count == 10, "Should keep only the matching private keys.")
        #expect(decoded.lastUserConfiguration.signedPublicOneTimeKeys.count == 10, "Should keep only the matching public keys.")

        // ✅ Second Test Case: Remote list has *no* matching keys
        _ = try await session.synchronizeLocalKeys(cache: session.cache!, keys: badKeys.map(\.id), type: .curve)

        let updatedDataFinal = try await store.findLocalSessionContext()
        let decryptedFinal = try crypto.decrypt(data: updatedDataFinal, symmetricKey: symmetricKey)
        let decodedFinal = try BSONDecoder().decode(SessionContext.self, from: Document(data: decryptedFinal!))
        #expect(decodedFinal.sessionUser.deviceKeys.privateOneTimeKeys.count == 0, "All private keys should be removed.")
        #expect(decodedFinal.lastUserConfiguration.signedPublicOneTimeKeys.count == 0, "All public keys should be removed.")
    }
    
    
    @Test
    func test_refreshOneTimeKeys_createsKeys_whenBelowThreshold() async throws {
        let mockCache = MockCache()
        let appSymmetricKey = await crypto.deriveStrictSymmetricKey(
            data: "secret".data(using: .utf8)!,
            salt: Data())
     
        func generateDatabaseEncryptionKey() -> Data {
            let databaseSymmetricKey = SymmetricKey(size: .bits256)
            return databaseSymmetricKey.withUnsafeBytes { Data($0) }
        }
        
        let bundle = try await CryptoSession.shared.createDeviceCryptographicBundle(isMaster: true)
        let sessionUser = SessionUser(
            secretName: "u1",
            deviceId: bundle.deviceKeys.deviceId,
            deviceKeys: bundle.deviceKeys,
            metadata: .init())
        let sessionContext = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: generateDatabaseEncryptionKey(),
            sessionContextId: .random(in: 1 ..< .max),
            lastUserConfiguration: bundle.userConfiguration,
            registrationState: .unregistered)
        let mockTransport = MockTransport(
            cache: mockCache,
            appKey: appSymmetricKey,
            publicKeys: bundle.userConfiguration.signedPublicOneTimeKeys)
        
        let data = try! BSONEncoder().encodeData(sessionContext)
        let encrypted = try crypto.encrypt(data: data, symmetricKey: appSymmetricKey)!
        try await mockCache.createLocalSessionContext(encrypted)
        await CryptoSession.shared.setSessionContext(sessionContext)
        await CryptoSession.shared.setTransportDelegate(conformer: mockTransport)
        await CryptoSession.shared.setDatabaseDelegate(conformer: mockCache)
        await CryptoSession.shared.setAppPassword("secret")

        
        let config = try await mockCache.findLocalSessionContext()
        let configurationData = try crypto.decrypt(data: config, symmetricKey: appSymmetricKey)!
        
        // Decode the session context from the decrypted data
        let foundContext = try BSONDecoder().decodeData(SessionContext.self, from: configurationData)
        
        // Run
        try await CryptoSession.shared.refreshOneTimeKeys(refreshType: .curve)
        
        #expect(foundContext.sessionUser.deviceKeys.privateOneTimeKeys.count == 100)
        #expect(foundContext.lastUserConfiguration.signedPublicOneTimeKeys.count == 100)

        for _ in (0..<100) {
            let prvSgnKey = try Curve25519.Signing.PrivateKey(rawRepresentation: foundContext.sessionUser.deviceKeys.privateSigningKey)
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let publicKey = try Curve25519PublicKeyRepresentable(id: id, privateKey.publicKey.rawRepresentation)
            let newOneTimeKey = try UserConfiguration.SignedPublicOneTimeKey(key: publicKey, deviceId: foundContext.sessionUser.deviceId, signingKey: prvSgnKey)
            _ = try await mockTransport.fetchOneTimeKey(for: "u1", deviceId: sessionUser.deviceId.uuidString, senderSecretName: "", sender: "")
            _ = try await mockTransport.updateOneTimeKeys(for: "u1", deviceId:  sessionUser.deviceId.uuidString, keys: [newOneTimeKey])
            
        }
        #expect(foundContext.lastUserConfiguration.signedPublicOneTimeKeys.count == 100)
        for _ in (0..<95) {
            _ = try await mockTransport.fetchOneTimeKey(
                for: "",
                deviceId: sessionUser.deviceId.uuidString,
                senderSecretName: "",
                sender: "")
        }
        
        #expect(foundContext.lastUserConfiguration.signedPublicOneTimeKeys.count == 100)
        await #expect(mockTransport.publicKeys.count == 105)
        
        try await CryptoSession.shared.refreshOneTimeKeys(refreshType: .curve)
        #expect(foundContext.lastUserConfiguration.signedPublicOneTimeKeys.count == 100)
        
        let config2 = try await mockCache.findLocalSessionContext()
        let configurationData2 = try crypto.decrypt(data: config2, symmetricKey: appSymmetricKey)!
        
        // Decode the session context from the decrypted data
        let foundContext3 = try BSONDecoder().decodeData(SessionContext.self, from: configurationData2)
        
        await #expect(mockTransport.publicKeys.count == 205)
        #expect(foundContext3.lastUserConfiguration.signedPublicOneTimeKeys.count == 100)
    }
}

actor MockCache: CryptoSessionStore {
    
    var localSessionData: Data = Data()
    func setLocalSessionData(_ data: Data) {
        localSessionData = data
    }
    
    func createLocalSessionContext(_ data: Data) async throws {
        self.localSessionData = data
    }
    
    func findLocalSessionContext() async throws -> Data {
        localSessionData
    }
    
    func findLocalDeviceSalt(keyData: Data) async throws -> Data {
       Data()
    }
    
    func deleteLocalDeviceSalt() async throws {
        
    }
    
    func updateLocalSessionContext(_ data: Data) async throws {
        self.localSessionData = data
    }
    
    func deleteLocalSessionContext() async throws {
        
    }
    
    func createSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {
        
    }
    
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] {
        []
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
    
    func removeContact(_ id: UUID) async throws {
        
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
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 0, sharedId: "", sequenceNumber: 0, data: Data())
    }
    
    func fetchMessage(by sharedMessageId: String) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 0, sharedId: "", sequenceNumber: 0, data: Data())
    }
    
    func createMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        
    }
    
    func updateMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        
    }
    
    func removeMessage(_ message: SessionModels.EncryptedMessage) async throws {
        
    }
    
    func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>, AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>.Continuation?) {
        // Create an empty AsyncThrowingStream
        let stream = AsyncThrowingStream<SessionModels.EncryptedMessage, Error> { continuation in
            // You can complete the stream here if needed
            continuation.finish()
        }
        
        // Return the empty stream and nil for the continuation
        return (stream, nil)
    }
    
    func messageCount(for sharedIdentifier: UUID) async throws -> Int {
        0
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
    
    func createMediaJob(_ packet: SessionModels.DataPacket) async throws {
        
    }
    
    func findAllMediaJobs() async throws -> [SessionModels.DataPacket] {
        []
    }
    
    func findMediaJobs(for recipient: String, symmetricKey: SymmetricKey) async throws -> [SessionModels.DataPacket] {
        []
    }
    
    func findMediaJob(for synchronizationIdentifier: String, symmetricKey: SymmetricKey) async throws -> SessionModels.DataPacket? {
     nil
    }
    
    func findMediaJob(_ id: UUID) async throws -> SessionModels.DataPacket? {
        nil
    }
    
    func deleteMediaJob(_ id: UUID) async throws {
        
    }
    
    
}

actor MockTransport: SessionTransport {
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {
        
    }
    
    func notifyIdentityCreation(for secretName: String, keys: SessionModels.OneTimeKeys) async throws {
        
    }
    
    
    let crypto = NeedleTailCrypto()
    let cache: MockCache
    let appKey: SymmetricKey
    var publicKeys: [UserConfiguration.SignedPublicOneTimeKey]
    
    // Generate 100 private one-time key pairs
    let privateOneTimeKeyPairs: [CryptoSession.KeyPair<Curve25519PublicKeyRepresentable, Curve25519PrivateKeyRepresentable>]
    let kyberOneTimeKeyPairs: [CryptoSession.KeyPair<Kyber1024PublicKeyRepresentable,Kyber1024PrivateKeyRepresentable>]

    init(cache: MockCache, appKey: SymmetricKey, publicKeys: [UserConfiguration.SignedPublicOneTimeKey]) {
        self.cache = cache
        self.appKey = appKey
        self.publicKeys = publicKeys
        
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
    
    func sendMessage(_ message: SessionModels.SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
        
    }
    
    func findConfiguration(for secretName: String) async throws -> SessionModels.UserConfiguration {
        let context = try await cache.findLocalSessionContext()
        let decrypted = try crypto.decrypt(data: context, symmetricKey: appKey)
        let decoded = try BSONDecoder().decode(SessionContext.self, from: Document(data: decrypted!))
        return decoded.lastUserConfiguration
    }
    
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient identity: UUID) async throws {
        
    }
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> [UUID] {
        publicKeys.map(\.id)
    }
    
    func fetchOneTimeKey(for secretName: String, deviceId: String, senderSecretName: String, sender keyId: String) async throws -> DoubleRatchetKit.Curve25519PublicKeyRepresentable {
        let context = try await cache.findLocalSessionContext()
        let decrypted = try crypto.decrypt(data: context, symmetricKey: appKey)
        let decoded = try BSONDecoder().decode(SessionContext.self, from: Document(data: decrypted!))
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: decoded.lastUserConfiguration.publicSigningKey)
        return try publicKeys.removeLast().verified(using: publicKey)!
    }
    
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedPublicOneTimeKey]) async throws {
        publicKeys.append(contentsOf: keys)
    }
    
    func deleteOneTimeKeys(for secretName: String, with id: String) async throws {
        
    }
    
    func createUploadPacket(secretName: String, deviceId: UUID, recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {
        
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
    
}
