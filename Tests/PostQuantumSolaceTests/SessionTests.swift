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
@testable import PQSSession

// MARK: - Test Suite
@Suite(.serialized)
actor SessionTests {
    
    // MARK: - Properties
    let session = PQSSession.shared
    let crypto = NeedleTailCrypto()
    
    // MARK: - Helper Types
    struct KeyPair {
        let id: UUID
        let publicKey: CurvePublicKey
        let privateKey: CurvePrivateKey
    }
    
    // MARK: - Cached Key Pairs
    private var senderCachedKeyPairs: [KeyPair]?
    private var badCachedKeyPairs: [KeyPair]?
    
    // MARK: - Helper Methods
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
    
    // MARK: - Tests
    @Test
    func testLocalKeySynchronization() async throws {
        await #expect(throws: Never.self, "Local key synchronization should complete without throwing any errors") {
            let store = MockIdentityStore(
                mockUserData: .init(session: self.session),
                session: self.session,
                isSender: false)
            
            let did = UUID()
            let senderltpk = self.crypto.generateCurve25519PrivateKey()
            let senderspk = self.crypto.generateCurve25519SigningPrivateKey()
            let senderDBSK = SymmetricKey(size: .bits256)
            
            // Generate 100 valid sender keys
            let validKeys = try self.senderOneTimeKeys()
            let badKeys = try self.badOneTimeKeys()
            
            let signedoneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try validKeys.map {
                try UserConfiguration.SignedOneTimePublicKey(
                    key: $0.publicKey,
                    deviceId: did,
                    signingKey: senderspk)
            }
            
            let kyberOneTimeKeyPairs: [PQSSession.KeyPair] = try (0..<100).map { _ in
                let id = UUID()
                let privateKey = try self.crypto.generateKyber1024PrivateSigningKey()
                let privateKeyRep = try PQKemPrivateKey(id: id, privateKey.encode())
                let publicKey = try PQKemPublicKey(id: id, privateKey.publicKey.rawRepresentation)
                return PQSSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
            }
            let finalKyber1024Key =  try self.crypto.generateKyber1024PrivateSigningKey()
            
            let sessionUser = SessionUser(
                secretName: "user1",
                deviceId: did,
                deviceKeys: .init(
                    deviceId: did,
                    signingPrivateKey: senderspk.rawRepresentation,
                    longTermPrivateKey: senderltpk.rawRepresentation,
                    oneTimePrivateKeys: validKeys.map(\.privateKey),
                    pqKemOneTimePrivateKeys: kyberOneTimeKeyPairs.map { $0.privateKey },
                    finalPQKemPrivateKey: try .init(finalKyber1024Key.encode())),
                metadata: .init())
            
            let signedPublicKyberOneTimeKeys: [UserConfiguration.SignedPQKemOneTimeKey] = try kyberOneTimeKeyPairs.map { keyPair in
                try UserConfiguration.SignedPQKemOneTimeKey(
                    key: keyPair.publicKey,
                    deviceId: did,
                    signingKey: senderspk)
            }
            
            let context = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: senderDBSK.withUnsafeBytes({ Data($0) }),
                sessionContextId: 123,
                activeUserConfiguration: .init(
                    signingPublicKey: senderspk.publicKey.rawRepresentation,
                    signedDevices: [],
                    signedOneTimePublicKeys: signedoneTimePublicKeys,
                    signedPQKemOneTimePublicKeys: signedPublicKyberOneTimeKeys),
                registrationState: .registered)
            
            await self.session.setAppPassword("123")
            let passwordData = await self.session.appPassword.data(using: .utf8)!
            let saltData = try await store.fetchLocalDeviceSalt(keyData: passwordData)
            let symmetricKey = await self.crypto.deriveStrictSymmetricKey(data: passwordData, salt: saltData)
            
            let data = try BSONEncoder().encodeData(context)
            let encryptedData = try self.crypto.encrypt(data: data, symmetricKey: symmetricKey)
            try await store.createLocalSessionContext(encryptedData!)
            await self.session.setDatabaseDelegate(conformer: store)
            
            // ✅ First Test Case: Remote list has *some* valid keys
            let partialKeys = Array(validKeys.prefix(10)).map(\.id)
            _ = try await self.session.synchronizeLocalKeys(cache: self.session.cache!, keys: partialKeys, type: .curve)
            
            
            let updatedData = try await store.fetchLocalSessionContext()
            let decrypted = try self.crypto.decrypt(data: updatedData, symmetricKey: symmetricKey)
            let decoded = try BSONDecoder().decode(SessionContext.self, from: Document(data: decrypted!))
            #expect(decoded.sessionUser.deviceKeys.oneTimePrivateKeys.count == 10, "Should keep only the matching private keys.")
            #expect(decoded.activeUserConfiguration.signedOneTimePublicKeys.count == 10, "Should keep only the matching public keys.")
            
            // ✅ Second Test Case: Remote list has *no* matching keys
            _ = try await self.session.synchronizeLocalKeys(cache: self.session.cache!, keys: badKeys.map(\.id), type: .curve)
            
            let updatedDataFinal = try await store.fetchLocalSessionContext()
            let decryptedFinal = try self.crypto.decrypt(data: updatedDataFinal, symmetricKey: symmetricKey)
            let decodedFinal = try BSONDecoder().decode(SessionContext.self, from: Document(data: decryptedFinal!))
            #expect(decodedFinal.sessionUser.deviceKeys.oneTimePrivateKeys.count == 0, "All private keys should be removed.")
            #expect(decodedFinal.activeUserConfiguration.signedOneTimePublicKeys.count == 0, "All public keys should be removed.")
        }
    }
    
    @Test
    func test_refreshOneTimeKeys_createsKeys_whenBelowThreshold() async throws {
        await #expect(throws: Never.self, "One-time key refresh should complete without throwing any errors when keys are below threshold") {
            let mockCache = MockCache()
            let appSymmetricKey = await self.crypto.deriveStrictSymmetricKey(
                data: "secret".data(using: .utf8)!,
                salt: Data())
            
            func generateDatabaseEncryptionKey() -> Data {
                let databaseSymmetricKey = SymmetricKey(size: .bits256)
                return databaseSymmetricKey.withUnsafeBytes { Data($0) }
            }
            
            let bundle = try await PQSSession.shared.createDeviceCryptographicBundle(isMaster: true)
            let sessionUser = SessionUser(
                secretName: "u1",
                deviceId: bundle.deviceKeys.deviceId,
                deviceKeys: bundle.deviceKeys,
                metadata: .init())
            let sessionContext = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: generateDatabaseEncryptionKey(),
                sessionContextId: .random(in: 1 ..< .max),
                activeUserConfiguration: bundle.userConfiguration,
                registrationState: .unregistered)
            let mockTransport = MockTransport(
                cache: mockCache,
                appKey: appSymmetricKey,
                publicKeys: bundle.userConfiguration.signedOneTimePublicKeys)
            
            let data = try! BSONEncoder().encodeData(sessionContext)
            let encrypted = try self.crypto.encrypt(data: data, symmetricKey: appSymmetricKey)!
            try await mockCache.createLocalSessionContext(encrypted)
            await PQSSession.shared.setSessionContext(sessionContext)
            await PQSSession.shared.setTransportDelegate(conformer: mockTransport)
            await PQSSession.shared.setDatabaseDelegate(conformer: mockCache)
            await PQSSession.shared.setAppPassword("secret")
            
            
            let config = try await mockCache.fetchLocalSessionContext()
            let configurationData = try self.crypto.decrypt(data: config, symmetricKey: appSymmetricKey)!
            
            // Decode the session context from the decrypted data
            let foundContext = try BSONDecoder().decodeData(SessionContext.self, from: configurationData)
            
            // Run
            try await PQSSession.shared.refreshOneTimeKeys(refreshType: .curve)
            
            #expect(foundContext.sessionUser.deviceKeys.oneTimePrivateKeys.count == 100)
            #expect(foundContext.activeUserConfiguration.signedOneTimePublicKeys.count == 100)
            
            for _ in (0..<100) {
                let prvSgnKey = try Curve25519.Signing.PrivateKey(rawRepresentation: foundContext.sessionUser.deviceKeys.signingPrivateKey)
                let id = UUID()
                let privateKey = self.crypto.generateCurve25519PrivateKey()
                let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
                let newOneTimeKey = try UserConfiguration.SignedOneTimePublicKey(key: publicKey, deviceId: foundContext.sessionUser.deviceId, signingKey: prvSgnKey)
                _ = try await mockTransport.fetchOneTimeKey(for: "u1", deviceId: sessionUser.deviceId.uuidString, senderSecretName: "", sender: "")
                _ = try await mockTransport.updateOneTimeKeys(for: "u1", deviceId:  sessionUser.deviceId.uuidString, keys: [newOneTimeKey])
                
            }
            #expect(foundContext.activeUserConfiguration.signedOneTimePublicKeys.count == 100)
            for _ in (0..<95) {
                _ = try await mockTransport.fetchOneTimeKey(
                    for: "",
                    deviceId: sessionUser.deviceId.uuidString,
                    senderSecretName: "",
                    sender: "")
            }
            
            #expect(foundContext.activeUserConfiguration.signedOneTimePublicKeys.count == 100)
            await #expect(mockTransport.publicKeys.count == 105)
            
            try await PQSSession.shared.refreshOneTimeKeys(refreshType: .curve)
            #expect(foundContext.activeUserConfiguration.signedOneTimePublicKeys.count == 100)
            
            let config2 = try await mockCache.fetchLocalSessionContext()
            let configurationData2 = try self.crypto.decrypt(data: config2, symmetricKey: appSymmetricKey)!
            
            // Decode the session context from the decrypted data
            let foundContext3 = try BSONDecoder().decodeData(SessionContext.self, from: configurationData2)
            
            await #expect(mockTransport.publicKeys.count == 205)
            #expect(foundContext3.activeUserConfiguration.signedOneTimePublicKeys.count == 100)
        }
    }
}

// MARK: - Mock Classes
actor MockCache: PQSSessionStore {
    
    var localSessionData: Data = Data()
    
    // MARK: - Session Context Methods
    func createLocalSessionContext(_ data: Data) async throws {
        self.localSessionData = data
    }
    
    func fetchLocalSessionContext() async throws -> Data {
        localSessionData
    }
    
    func updateLocalSessionContext(_ data: Data) async throws {
        self.localSessionData = data
    }
    
    func deleteLocalSessionContext() async throws {}
    
    // MARK: - Device Salt Methods
    func fetchLocalDeviceSalt(keyData: Data) async throws -> Data {
        Data()
    }
    
    func deleteLocalDeviceSalt() async throws {}
    
    // MARK: - Session Identity Methods
    func createSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {}
    func fetchSessionIdentities() async throws -> [DoubleRatchetKit.SessionIdentity] { [] }
    func updateSessionIdentity(_ session: DoubleRatchetKit.SessionIdentity) async throws {}
    func deleteSessionIdentity(_ id: UUID) async throws {}
    
    // MARK: - Contact Methods
    func fetchContacts() async throws -> [SessionModels.ContactModel] { [] }
    func createContact(_ contact: SessionModels.ContactModel) async throws {}
    func updateContact(_ contact: SessionModels.ContactModel) async throws {}
    func deleteContact(_ id: UUID) async throws {}
    
    // MARK: - Communication Methods
    func fetchCommunications() async throws -> [SessionModels.BaseCommunication] { [] }
    func createCommunication(_ type: SessionModels.BaseCommunication) async throws {}
    func updateCommunication(_ type: SessionModels.BaseCommunication) async throws {}
    func deleteCommunication(_ type: SessionModels.BaseCommunication) async throws {}
    
    // MARK: - Message Methods
    func fetchMessages(sharedCommunicationId: UUID) async throws -> [MessageRecord] { [] }
    
    func fetchMessage(id messageId: UUID) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 0, sharedId: "", sequenceNumber: 0, data: Data())
    }
    
    func fetchMessage(sharedId sharedMessageId: String) async throws -> SessionModels.EncryptedMessage {
        try .init(id: UUID(), communicationId: UUID(), sessionContextId: 0, sharedId: "", sequenceNumber: 0, data: Data())
    }
    
    func createMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
    func updateMessage(_ message: SessionModels.EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
    func deleteMessage(_ message: SessionModels.EncryptedMessage) async throws {}
    
    func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>, AsyncThrowingStream<SessionModels.EncryptedMessage, any Error>.Continuation?) {
        let stream = AsyncThrowingStream<SessionModels.EncryptedMessage, Error> { continuation in
            continuation.finish()
        }
        return (stream, nil)
    }
    
    func messageCount(sharedIdentifier: UUID) async throws -> Int { 0 }
    
    // MARK: - Job Methods
    func fetchJobs() async throws -> [SessionModels.JobModel] { [] }
    func createJob(_ job: SessionModels.JobModel) async throws {}
    func updateJob(_ job: SessionModels.JobModel) async throws {}
    func deleteJob(_ job: SessionModels.JobModel) async throws {}
    
    // MARK: - Media Job Methods
    func createMediaJob(_ packet: SessionModels.DataPacket) async throws {}
    func fetchAllMediaJobs() async throws -> [SessionModels.DataPacket] { [] }
    func fetchMediaJobs(recipient: String, symmetricKey: SymmetricKey) async throws -> [SessionModels.DataPacket] { [] }
    func fetchMediaJob(synchronizationIdentifier: String, symmetricKey: SymmetricKey) async throws -> SessionModels.DataPacket? { nil }
    func fetchMediaJob(id: UUID) async throws -> SessionModels.DataPacket? { nil }
    func deleteMediaJob(_ id: UUID) async throws {}
}

actor MockTransport: SessionTransport {
    let crypto = NeedleTailCrypto()
    let cache: MockCache
    let appKey: SymmetricKey
    var publicKeys: [UserConfiguration.SignedOneTimePublicKey]
    
    // Generate 100 private one-time key pairs
    let privateOneTimeKeyPairs: [PQSSession.KeyPair<CurvePublicKey, CurvePrivateKey>]
    let kyberOneTimeKeyPairs: [PQSSession.KeyPair<PQKemPublicKey,PQKemPrivateKey>]
    
    init(cache: MockCache, appKey: SymmetricKey, publicKeys: [UserConfiguration.SignedOneTimePublicKey]) {
        self.cache = cache
        self.appKey = appKey
        self.publicKeys = publicKeys
        
        privateOneTimeKeyPairs = try! (0..<100).map { _ in
            let crypto = NeedleTailCrypto()
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let privateKeyRep = try CurvePrivateKey(id: id, privateKey.rawRepresentation)
            let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return PQSSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }
        
        kyberOneTimeKeyPairs = try! (0..<100).map { _ in
            let crypto = NeedleTailCrypto()
            let id = UUID()
            let privateKey = try crypto.generateKyber1024PrivateSigningKey()
            let privateKeyRep = try PQKemPrivateKey(id: id, privateKey.encode())
            let publicKey = try PQKemPublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return PQSSession.KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }
    }
    
    // MARK: - Transport Methods
    func sendMessage(_ message: SessionModels.SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {}
    func findConfiguration(for secretName: String) async throws -> SessionModels.UserConfiguration {
        let context = try await cache.fetchLocalSessionContext()
        let decrypted = try crypto.decrypt(data: context, symmetricKey: appKey)
        let decoded = try BSONDecoder().decode(SessionContext.self, from: Document(data: decrypted!))
        return decoded.activeUserConfiguration
    }
    func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient identity: UUID) async throws {}
    func createUploadPacket(secretName: String, deviceId: UUID, recipient: SessionModels.MessageRecipient, metadata: BSON.Document) async throws {}
    func notifyIdentityCreation(for secretName: String, keys: SessionModels.OneTimeKeys) async throws {}
    func publishRotatedKeys(for secretName: String, deviceId: String, rotated keys: SessionModels.RotatedPublicKeys) async throws {}
    
    // MARK: - One Time Key Methods
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> [UUID] {
        publicKeys.map(\.id)
    }
    
    func fetchOneTimeKey(for secretName: String, deviceId: String, senderSecretName: String, sender keyId: String) async throws -> DoubleRatchetKit.CurvePublicKey {
        let context = try await cache.fetchLocalSessionContext()
        let decrypted = try crypto.decrypt(data: context, symmetricKey: appKey)
        let decoded = try BSONDecoder().decode(SessionContext.self, from: Document(data: decrypted!))
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: decoded.activeUserConfiguration.signingPublicKey)
        return try publicKeys.removeLast().verified(using: publicKey)!
    }
    
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedOneTimePublicKey]) async throws {
        publicKeys.append(contentsOf: keys)
    }
    
    func deleteOneTimeKeys(for secretName: String, with id: String) async throws {}
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: SessionModels.KeysType) async throws {}
    
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> SessionModels.OneTimeKeys {
        guard let privateKey = privateOneTimeKeyPairs.last else { fatalError() }
        guard let privateKyberKey = kyberOneTimeKeyPairs.last else { fatalError() }
        return SessionModels.OneTimeKeys(curve: privateKey.publicKey, kyber: privateKyberKey.publicKey)
    }
    
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] {
        privateOneTimeKeyPairs.map { $0.publicKey.id }
    }
    
    func updateOneTimePQKemKeys(for secretName: String, deviceId: String, keys: [SessionModels.UserConfiguration.SignedPQKemOneTimeKey]) async throws {}
    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {}
}
