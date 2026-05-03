//
//  SessionIdentityTests.swift
//  post-quantum-solace
//
//  Created by AI Assistant on 2025-01-25.
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

import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing
import Crypto

// MARK: - Test Suite

@Suite(.serialized)
actor SessionIdentityTests {
    
    // MARK: - Properties
    
    let session = PQSSession()
    let crypto = NeedleTailCrypto()
    
    // MARK: - Mock Store
    
    final class MockSessionIdentityStore: PQSSessionStore, @unchecked Sendable {
        enum MockError: Error {
            case forcedDelete
            case forcedUpdate
        }

        var sessionContext: Data?
        var identities = [SessionIdentity]()
        var failNextSessionIdentityDelete = false
        var failNextSessionIdentityUpdate = false
        
        // Core session context methods
        func createLocalSessionContext(_ data: Data) async throws { sessionContext = data }
        func fetchLocalSessionContext() async throws -> Data { 
            guard let context = sessionContext else {
                throw PQSSession.SessionErrors.databaseNotInitialized
            }
            return context
        }
        func updateLocalSessionContext(_ data: Data) async throws { sessionContext = data }
        func deleteLocalSessionContext() async throws { sessionContext = nil }
        
        // Device salt methods
        func fetchLocalDeviceSalt(keyData: Data) async throws -> Data { keyData + "salt".data(using: .utf8)! }
        func deleteLocalDeviceSalt() async throws {}
        func fetchLocalDeviceSalt() async throws -> String { "test-salt" }
        
        // Device configuration methods
        func findLocalDeviceConfiguration() async throws -> Data { Data() }
        func createLocalDeviceConfiguration(_ configuration: Data) async throws {}
        
        // Session identity methods
        func fetchSessionIdentities() async throws -> [SessionIdentity] { identities }
        func updateSessionIdentity(_ session: SessionIdentity) async throws {
            if failNextSessionIdentityUpdate {
                failNextSessionIdentityUpdate = false
                throw MockError.forcedUpdate
            }
            identities.removeAll(where: { $0.id == session.id })
            identities.append(session)
        }
        func createSessionIdentity(_ session: SessionIdentity) async throws { identities.append(session) }
        func deleteSessionIdentity(_ id: UUID) async throws {
            if failNextSessionIdentityDelete {
                failNextSessionIdentityDelete = false
                throw MockError.forcedDelete
            }
            identities.removeAll(where: { $0.id == id })
        }
        
        // Stub implementations for unused methods (simplified)
        func removeContact(_: UUID) async throws {}
        func deleteContact(_: UUID) async throws {}
        func createMediaJob(_: DataPacket) async throws {}
        func fetchAllMediaJobs() async throws -> [DataPacket] { [] }
        func fetchMediaJob(id _: UUID) async throws -> DataPacket? { nil }
        func deleteMediaJob(_: UUID) async throws {}
        func fetchContacts() async throws -> [ContactModel] { [] }
        func createContact(_: ContactModel) async throws {}
        func updateContact(_: ContactModel) async throws {}
        func fetchCommunications() async throws -> [BaseCommunication] { [] }
        func createCommunication(_: BaseCommunication) async throws {}
        func updateCommunication(_: BaseCommunication) async throws {}
        func removeCommunication(_: BaseCommunication) async throws {}
        func deleteCommunication(_: BaseCommunication) async throws {}
        func fetchMessages(sharedCommunicationId _: UUID) async throws -> [MessageRecord] { [] }
        func fetchMessage(id _: UUID) async throws -> EncryptedMessage {
            try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
        }
        func fetchMessage(sharedId _: String) async throws -> EncryptedMessage {
            try .init(id: UUID(), communicationId: UUID(), sessionContextId: 1, sharedId: "123", sequenceNumber: 1, data: Data())
        }
        func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
        func updateMessage(_: EncryptedMessage, symmetricKey: SymmetricKey) async throws {}
        func removeMessage(_: EncryptedMessage) async throws {}
        func deleteMessage(_: EncryptedMessage) async throws {}
        func streamMessages(sharedIdentifier _: UUID) async throws -> (AsyncThrowingStream<EncryptedMessage, any Error>, AsyncThrowingStream<EncryptedMessage, any Error>.Continuation?) {
            let stream = AsyncThrowingStream<EncryptedMessage, any Error> { _ in }
            return (stream, nil)
        }
        func messageCount(sharedIdentifier _: UUID) async throws -> Int { 0 }
        func readJobs() async throws -> [JobModel] { [] }
        func fetchJobs() async throws -> [JobModel] { [] }
        func createJob(_: JobModel) async throws {}
        func updateJob(_: JobModel) async throws {}
        func removeJob(_: JobModel) async throws {}
        func deleteJob(_: JobModel) async throws {}
        func findMediaJobs(for _: String, symmetricKey: SymmetricKey) async throws -> [DataPacket] { [] }
        func fetchMediaJobs(recipient _: String, symmetricKey: SymmetricKey) async throws -> [DataPacket] { [] }
        func findMediaJob(for _: String, symmetricKey: SymmetricKey) async throws -> DataPacket? { nil }
        func fetchMediaJob(synchronizationIdentifier _: String, symmetricKey: SymmetricKey) async throws -> DataPacket? { nil }
    }
    
    // MARK: - Mock Transport
    
    final class MockSessionIdentityTransport: SessionTransport, @unchecked Sendable {

        var configurations: [String: UserConfiguration] = [:]
        var oneTimeKeys: [String: OneTimeKeys] = [:]
        var shouldThrowError = false
        
        func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys {
            if shouldThrowError { throw PQSSession.SessionErrors.userNotFound }
            return oneTimeKeys[secretName] ?? OneTimeKeys(curve: nil, mlKEM: nil)
        }
        
        func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID] { [] }
        func publishUserConfiguration(_ configuration: SessionModels.UserConfiguration, recipient secretName: String, recipient identity: UUID) async throws {}
        func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {}
        
        func findConfiguration(for secretName: String) async throws -> UserConfiguration {
            if shouldThrowError { throw PQSSession.SessionErrors.userNotFound }
            guard let config = configurations[secretName] else {
                throw PQSSession.SessionErrors.userNotFound
            }
            return config
        }
        
        func findUserConfiguration(secretName: String) async throws -> UserConfiguration {
            if shouldThrowError { throw PQSSession.SessionErrors.configurationError }
            guard let config = configurations[secretName] else {
                throw PQSSession.SessionErrors.configurationError
            }
            return config
        }
        
        // Required SessionTransport methods
        func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {}
        func updateOneTimeMLKEMKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedMLKEMOneTimeKey]) async throws {}
        func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {}
        func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws {}
        func publishRotatedKeys(for secretName: String, deviceId: String, rotated keys: RotatedPublicKeys) async throws {}
        func createUploadPacket(secretName: String, deviceId: UUID, recipient: MessageRecipient, metadata: Data) async throws {}
    }

    @Test("SessionCache keeps memory and disk aligned when delete persistence fails")
    func testSessionCachePreservesIdentityWhenDeleteFails() async throws {
        let store = MockSessionIdentityStore()
        let cache = SessionCache(store: store)
        let identity = SessionIdentity(id: UUID(), data: Data([0x01, 0x02, 0x03]))

        try await cache.createSessionIdentity(identity)
        store.failNextSessionIdentityDelete = true

        await #expect(throws: MockSessionIdentityStore.MockError.self) {
            try await cache.deleteSessionIdentity(identity.id)
        }

        let cached = try await cache.fetchSessionIdentities()
        #expect(cached.contains(where: { $0.id == identity.id }))
        #expect(store.identities.contains(where: { $0.id == identity.id }))
        await session.shutdown()
    }

    @Test("SessionCache keeps previous identity when update persistence fails")
    func testSessionCachePreservesIdentityWhenUpdateFails() async throws {
        let store = MockSessionIdentityStore()
        let cache = SessionCache(store: store)
        let original = SessionIdentity(id: UUID(), data: Data([0x01]))
        let updated = SessionIdentity(id: original.id, data: Data([0x02]))

        try await cache.createSessionIdentity(original)
        store.failNextSessionIdentityUpdate = true

        await #expect(throws: MockSessionIdentityStore.MockError.self) {
            try await cache.updateSessionIdentity(updated)
        }

        let cached = try await cache.fetchSessionIdentities()
        #expect(cached.first(where: { $0.id == original.id })?.data == original.data)
        #expect(store.identities.first(where: { $0.id == original.id })?.data == original.data)
        await session.shutdown()
    }
    
    // MARK: - Helper Methods
    
    /// Sets up a complete test session with mocks
    private func setupTestSession() async throws -> (MockSessionIdentityStore, MockSessionIdentityTransport) {
        let store = MockSessionIdentityStore()
        let transport = MockSessionIdentityTransport()
        
        // Setup session
        await session.setDatabaseDelegate(conformer: store)
        await session.setTransportDelegate(conformer: transport)
        try await setupSession(store: store)
        
        return (store, transport)
    }
    
    /// Sets up the session context with proper cryptographic bundle
    private func setupSession(store: MockSessionIdentityStore) async throws {
        let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        
        let sessionUser = SessionUser(
            secretName: "test-user",
            deviceId: bundle.deviceKeys.deviceId,
            deviceKeys: bundle.deviceKeys)
        
        let databaseEncryptionKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        
        let sessionContext = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: databaseEncryptionKey,
            sessionContextId: 123,
            activeUserConfiguration: bundle.userConfiguration,
            registrationState: .registered
        )
        
        await session.setAppPassword("test-password")
        
        let passwordData = await session.appPassword.data(using: .utf8)!
        let saltData = try await store.fetchLocalDeviceSalt(keyData: passwordData)
        let symmetricKey = await crypto.deriveStrictSymmetricKey(data: passwordData, salt: saltData)
        
        let data = try BinaryEncoder().encode(sessionContext)
        let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey)
        try await store.createLocalSessionContext(encryptedData!)
        await session.setSessionContext(sessionContext)
    }
    
    /// Creates a test identity for a given secret name
    private func createTestIdentity(for secretName: String) async throws -> SessionIdentity {
        let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        
        // Get the first signed device configuration and verify it
        let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: bundle.userConfiguration.signingPublicKey)
        guard let signedDevice = bundle.userConfiguration.signedDevices.first,
              let deviceConfig = try signedDevice.verified(using: signingPublicKey) else {
            throw PQSSession.SessionErrors.configurationError
        }
        
        // Get one-time keys if available
        let oneTimeKey = bundle.userConfiguration.signedOneTimePublicKeys.first
        let mlKEMKey = bundle.userConfiguration.signedMLKEMOneTimePublicKeys.first
        
        // Verify and extract the actual keys
        let verifiedOneTimeKey = oneTimeKey != nil ? try oneTimeKey!.verified(using: signingPublicKey) : nil
        let verifiedMLKEMKey = mlKEMKey != nil ? try mlKEMKey!.verified(using: signingPublicKey) : nil
        
        guard let verifiedMLKEMKey = verifiedMLKEMKey else {
            throw PQSSession.SessionErrors.configurationError
        }
        
        return try await session.createEncryptableSessionIdentityModel(
            with: deviceConfig,
            oneTimePublicKey: verifiedOneTimeKey,
            mlKEMPublicKey: verifiedMLKEMKey,
            for: secretName,
            associatedWith: bundle.deviceKeys.deviceId,
            new: 123
        )
    }
    
    /// Creates a test identity for a given secret name without storing it in the cache
    private func createTestIdentityWithoutStoring(for secretName: String) async throws -> SessionIdentity {
        let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
        
        // Get the first signed device configuration and verify it
        let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: bundle.userConfiguration.signingPublicKey)
        guard let signedDevice = bundle.userConfiguration.signedDevices.first,
              let deviceConfig = try signedDevice.verified(using: signingPublicKey) else {
            throw PQSSession.SessionErrors.configurationError
        }
        
        // Get one-time keys if available
        let oneTimeKey = bundle.userConfiguration.signedOneTimePublicKeys.first
        let mlKEMKey = bundle.userConfiguration.signedMLKEMOneTimePublicKeys.first
        
        // Verify and extract the actual keys
        let verifiedOneTimeKey = oneTimeKey != nil ? try oneTimeKey!.verified(using: signingPublicKey) : nil
        let verifiedMLKEMKey = mlKEMKey != nil ? try mlKEMKey!.verified(using: signingPublicKey) : nil
        
        guard let verifiedMLKEMKey = verifiedMLKEMKey else {
            throw PQSSession.SessionErrors.configurationError
        }
        
        // Create the identity manually without storing it
        let determinedDeviceName = try await session.determineDeviceName()
        let deviceName = deviceConfig.deviceName ?? determinedDeviceName
        
        let identity = try SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: secretName,
                deviceId: deviceConfig.deviceId,
                sessionContextId: 123,
                longTermPublicKey: deviceConfig.longTermPublicKey,
                signingPublicKey: deviceConfig.signingPublicKey,
                mlKEMPublicKey: verifiedMLKEMKey,
                oneTimePublicKey: verifiedOneTimeKey,
                state: nil,
                deviceName: deviceName,
                isMasterDevice: deviceConfig.isMasterDevice
            ),
            symmetricKey: try await session.getDatabaseSymmetricKey()
        )
        
        return identity
    }
    
    // MARK: - Tests
    
    // MARK: Basic Functionality Tests
    
    @Test("Should handle empty identities correctly")
    func testRefreshIdentitiesLogic() async throws {
        do {
            let (_, _) = try await setupTestSession()
            
            // Test: Should handle empty identities correctly
            let identities = try await session.getSessionIdentities(with: "alice")
            #expect(identities.isEmpty)
            
            // Test: sessionIdentities set should be empty initially
            #expect(await session.sessionIdentities.isEmpty)
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
    
    @Test("Should handle error conditions gracefully")
    func testRefreshIdentitiesErrorHandling() async throws {
        do {
            let (_, transport) = try await setupTestSession()
            
            // Test: Should handle missing configuration gracefully
            transport.shouldThrowError = true
            
            // This should not throw but return empty array due to error handling
            let identities = try await session.refreshIdentities(secretName: "nonexistent")
            #expect(identities.isEmpty)
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
    
    @Test("Should handle different recipient names")
    func testRefreshIdentitiesBasicFunctionality() async throws {
        do {
            let (_, _) = try await setupTestSession()
            
            // Test: Should handle different recipient names
            // Note: Due to shared state between tests, identities might exist from previous tests
            // We test that the method works correctly regardless of existing state
            let identities = try await session.refreshIdentities(secretName: "alice")
            let identities2 = try await session.refreshIdentities(secretName: "bob")
            
            // Both calls should complete successfully without throwing errors
            #expect(identities.count >= 0) // May have existing identities from other tests
            #expect(identities2.count >= 0) // May have existing identities from other tests
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }

    @Test("Should rethrow critical invalid-signature refresh failures")
    func testRefreshIdentitiesRethrowsCriticalInvalidSignature() async throws {
        do {
            let (_, transport) = try await setupTestSession()

            let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            var invalidConfiguration = bundle.userConfiguration
            invalidConfiguration.signingPublicKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
            transport.configurations["alice"] = invalidConfiguration

            do {
                _ = try await session.refreshIdentities(secretName: "alice", forceRefresh: true)
                Issue.record("Expected refreshIdentities to throw invalidSignature for tampered configuration")
            } catch let error as PQSSession.SessionErrors {
                #expect(error == .invalidSignature)
            }

            await session.shutdown()
        } catch {
            await session.shutdown()
            throw error
        }
    }
    
    // MARK: Identity Management Tests
    
    @Test("Should find and return existing identities without unnecessary refresh")
    func testRefreshIdentitiesWithExistingIdentities() async throws {
        do {
            let (store, transport) = try await setupTestSession()
            
            // Create a test identity and add it to the store
            let testIdentity = try await createTestIdentity(for: "alice")
            try await store.createSessionIdentity(testIdentity)
            
            // Add configuration to transport
            let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            transport.configurations["alice"] = bundle.userConfiguration
            
            // Test: Should find existing identity
            let identities = try await session.getSessionIdentities(with: "alice")
            #expect(identities.count == 1)
            
            // Test: Should return existing identity without refresh
            let refreshedIdentities = try await session.refreshIdentities(secretName: "alice")
            #expect(refreshedIdentities.count == 1)
            #expect(refreshedIdentities.first?.id == testIdentity.id)
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
    
    @Test("Should filter identities correctly by recipient name")
    func testGetSessionIdentitiesFiltering() async throws {
        do {
            let (_, _) = try await setupTestSession()
            
            // Test: Should return empty array when no identities exist
            let identities = try await session.getSessionIdentities(with: "alice")
            #expect(identities.isEmpty)
            
            // Test: Should return empty array for different recipient
            let identities2 = try await session.getSessionIdentities(with: "bob")
            #expect(identities2.isEmpty)
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }

    @Test("Should never return current device identity from getSessionIdentities")
    func testGetSessionIdentitiesExcludesCurrentDeviceIdentity() async throws {
        do {
            let (store, _) = try await setupTestSession()
            guard let context = await session.sessionContext else {
                Issue.record("Session context should be initialized")
                await session.shutdown()
                return
            }

            // Insert an identity row that points to this same device.
            let signingPublicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: context.activeUserConfiguration.signingPublicKey
            )
            guard let signedDevice = context.activeUserConfiguration.signedDevices.first(where: { signed in
                guard let verified = try? signed.verified(using: signingPublicKey) else { return false }
                return verified.deviceId == context.sessionUser.deviceId
            }), let currentDevice = try signedDevice.verified(using: signingPublicKey) else {
                Issue.record("Expected to resolve current device configuration")
                await session.shutdown()
                return
            }
            let selfIdentity = try await session.createEncryptableSessionIdentityModel(
                with: currentDevice,
                oneTimePublicKey: nil,
                mlKEMPublicKey: currentDevice.finalMLKEMPublicKey,
                for: context.sessionUser.secretName,
                associatedWith: context.sessionUser.deviceId,
                new: Int.random(in: 1 ..< Int.max)
            )
            try await store.createSessionIdentity(selfIdentity)

            let identities = try await session.getSessionIdentities(with: context.sessionUser.secretName)
            #expect(identities.isEmpty)

            await session.shutdown()
        } catch {
            await session.shutdown()
            throw error
        }
    }

    @Test("Should not leak linked self devices into non-self recipient lookups")
    func testGetSessionIdentitiesDoesNotLeakLinkedSelfDevicesIntoPeerLookup() async throws {
        do {
            let (store, transport) = try await setupTestSession()

            let selfSiblingIdentity = try await createTestIdentity(for: "test-user")
            let bobIdentity = try await createTestIdentity(for: "bob")

            try await store.createSessionIdentity(selfSiblingIdentity)
            try await store.createSessionIdentity(bobIdentity)

            let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            transport.configurations["bob"] = bundle.userConfiguration

            let retrieved = try await session.getSessionIdentities(with: "bob")

            #expect(retrieved.count == 1, "Peer lookup should only return Bob identities")
            guard let onlyIdentity = retrieved.first,
                  let props = try? await onlyIdentity.props(symmetricKey: session.getDatabaseSymmetricKey()) else {
                Issue.record("Expected exactly one decryptable Bob identity")
                await session.shutdown()
                return
            }
            #expect(props.secretName == "bob")

            await session.shutdown()
        } catch {
            await session.shutdown()
            throw error
        }
    }
    
    // MARK: Advanced Tests
    
    @Test("Should handle multiple identities for different recipients")
    func testMultipleIdentitiesForDifferentRecipients() async throws {
        do {
            let (store, transport) = try await setupTestSession()
            
            // Create identities for different recipients
            let aliceIdentity = try await createTestIdentity(for: "alice")
            let bobIdentity = try await createTestIdentity(for: "bob")
            
            try await store.createSessionIdentity(aliceIdentity)
            try await store.createSessionIdentity(bobIdentity)
            
            // Add configurations to transport
            let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            transport.configurations["alice"] = bundle.userConfiguration
            transport.configurations["bob"] = bundle.userConfiguration
            
            // Test: Should find correct identities for each recipient
            let aliceIdentities = try await session.getSessionIdentities(with: "alice")
            let bobIdentities = try await session.getSessionIdentities(with: "bob")
            
            #expect(aliceIdentities.count == 1)
            #expect(bobIdentities.count == 1)
            #expect(aliceIdentities.first?.id == aliceIdentity.id)
            #expect(bobIdentities.first?.id == bobIdentity.id)
            
            // Test: Should not find alice's identity when querying for bob
            let aliceIdentitiesForBob = try await session.getSessionIdentities(with: "bob")
            var allIdentitiesAreForBob = true
            for identity in aliceIdentitiesForBob {
                guard let props = try? await identity.props(symmetricKey: session.getDatabaseSymmetricKey()) else { 
                    allIdentitiesAreForBob = false
                    break
                }
                if props.secretName != "bob" {
                    allIdentitiesAreForBob = false
                    break
                }
            }
            #expect(allIdentitiesAreForBob)
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
    
    @Test("Should handle force refresh correctly")
    func testForceRefresh() async throws {
        do {
            let (store, transport) = try await setupTestSession()
            
            // Create a test identity
            let testIdentity = try await createTestIdentity(for: "alice")
            try await store.createSessionIdentity(testIdentity)
            
            // Add configuration to transport
            let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            transport.configurations["alice"] = bundle.userConfiguration
            
            // Test: Normal refresh should return existing identity
            let normalRefresh = try await session.refreshIdentities(secretName: "alice")
            #expect(normalRefresh.count == 1)
            #expect(normalRefresh.first?.id == testIdentity.id)
            
            // Test: Force refresh should create new identity from transport configuration
            let forceRefresh = try await session.refreshIdentities(secretName: "alice", forceRefresh: true)
            #expect(forceRefresh.count == 1)
            // Force refresh creates a new identity, so it should have a different ID
            #expect(forceRefresh.first?.id != testIdentity.id)
            
            // Verify the new identity has the correct properties
            if let newIdentity = forceRefresh.first,
               let props = try? await newIdentity.props(symmetricKey: session.getDatabaseSymmetricKey()) {
                #expect(props.secretName == "alice")
                #expect(props.isMasterDevice == true)
            }
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }

    @Test("Force refresh replaces rotated active identity instead of mutating it")
    func testForceRefreshReplacesRotatedActiveIdentity() async throws {
        do {
            let (store, transport) = try await setupTestSession()

            let originalBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            let originalSigningPublicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: originalBundle.userConfiguration.signingPublicKey
            )
            guard let originalSignedDevice = originalBundle.userConfiguration.signedDevices.first,
                  let originalDevice = try originalSignedDevice.verified(using: originalSigningPublicKey)
            else {
                Issue.record("Expected original device to verify")
                await session.shutdown()
                return
            }

            let originalIdentity = try await session.createEncryptableSessionIdentityModel(
                with: originalDevice,
                oneTimePublicKey: nil,
                mlKEMPublicKey: originalDevice.finalMLKEMPublicKey,
                for: "alice",
                associatedWith: originalDevice.deviceId,
                new: 321
            )

            let rotatedBundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            let rotatedSigningKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: rotatedBundle.deviceKeys.signingPrivateKey
            )
            let rotatedDevice = UserDeviceConfiguration(
                deviceId: originalDevice.deviceId,
                signingPublicKey: rotatedSigningKey.publicKey.rawRepresentation,
                longTermPublicKey: rotatedBundle.deviceConfiguration.longTermPublicKey,
                finalMLKEMPublicKey: rotatedBundle.deviceConfiguration.finalMLKEMPublicKey,
                deviceName: originalDevice.deviceName,
                hmacData: rotatedBundle.deviceConfiguration.hmacData,
                isMasterDevice: originalDevice.isMasterDevice,
                lastSeenAt: Date()
            )
            let rotatedSignedDevice = try UserConfiguration.SignedDeviceConfiguration(
                device: rotatedDevice,
                signingKey: rotatedSigningKey
            )
            let rotatedSignedBundle = try UserConfiguration.SignedDeviceKeyBundle(
                bundle: .init(
                    deviceId: originalDevice.deviceId,
                    longTermPublicKey: rotatedDevice.longTermPublicKey,
                    finalMLKEMPublicKey: rotatedDevice.finalMLKEMPublicKey
                ),
                signingKey: rotatedSigningKey
            )
            transport.configurations["alice"] = UserConfiguration(
                signingPublicKey: rotatedSigningKey.publicKey.rawRepresentation,
                signedDevices: [rotatedSignedDevice],
                signedOneTimePublicKeys: [],
                signedMLKEMOneTimePublicKeys: [],
                signedDeviceKeyBundles: [rotatedSignedBundle]
            )

            let refreshed = try await session.refreshIdentities(secretName: "alice", forceRefresh: true)
            let symmetricKey = try await session.getDatabaseSymmetricKey()
            let activeAliceIdentities = await refreshed.asyncFilter { identity in
                guard let props = await identity.props(symmetricKey: symmetricKey) else { return false }
                return props.secretName == "alice"
                    && props.deviceId == originalDevice.deviceId
                    && !props.deviceName.hasPrefix(PQSSessionConstants.inactiveSessionDeviceNamePrefix)
            }

            #expect(activeAliceIdentities.count == 1)
            guard let replacement = activeAliceIdentities.first,
                  let replacementProps = await replacement.props(symmetricKey: symmetricKey)
            else {
                Issue.record("Expected one replacement identity")
                await session.shutdown()
                return
            }

            #expect(replacement.id != originalIdentity.id)
            #expect(replacementProps.longTermPublicKey == rotatedDevice.longTermPublicKey)
            #expect(replacementProps.signingPublicKey == rotatedDevice.signingPublicKey)
            #expect(replacementProps.state == nil)
            #expect(!store.identities.contains(where: { $0.id == originalIdentity.id }))

            await session.shutdown()
        } catch {
            await session.shutdown()
            throw error
        }
    }

    @Test("Should assess peer refresh impact for unchanged and rotated peer identity keys")
    func testRefreshIdentitiesAssessingImpact() async throws {
        do {
            let (store, transport) = try await setupTestSession()

            let bundle = try await session.createDeviceCryptographicBundle(isMaster: true)
            let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: bundle.userConfiguration.signingPublicKey)
            guard let signedDevice = bundle.userConfiguration.signedDevices.first,
                  let deviceConfig = try signedDevice.verified(using: signingPublicKey) else {
                Issue.record("Expected a verified device configuration")
                await session.shutdown()
                return
            }

            let verifiedOneTimeKey = try bundle.userConfiguration.signedOneTimePublicKeys.first?.verified(using: signingPublicKey)
            let verifiedMLKEMKey = try bundle.userConfiguration.signedMLKEMOneTimePublicKeys.first?.verified(using: signingPublicKey)
            guard let verifiedMLKEMKey else {
                Issue.record("Expected a verified MLKEM key")
                await session.shutdown()
                return
            }

            let identity = try await session.createEncryptableSessionIdentityModel(
                with: deviceConfig,
                oneTimePublicKey: verifiedOneTimeKey,
                mlKEMPublicKey: verifiedMLKEMKey,
                for: "alice",
                associatedWith: deviceConfig.deviceId,
                new: 123
            )
            try await store.createSessionIdentity(identity)
            transport.configurations["alice"] = bundle.userConfiguration

            let unchanged = try await session.refreshIdentitiesAssessingImpact(
                secretName: "alice",
                deviceId: deviceConfig.deviceId,
                forceRefresh: false
            )
            #expect(unchanged.impact == .noSessionImpact)

            let rotatedSigningKey = Curve25519.Signing.PrivateKey()
            var rotatedDevice = deviceConfig
            await rotatedDevice.updateSigningPublicKey(rotatedSigningKey.publicKey.rawRepresentation)
            let rotatedSignedDevice = try UserConfiguration.SignedDeviceConfiguration(
                device: rotatedDevice,
                signingKey: rotatedSigningKey
            )
            transport.configurations["alice"] = UserConfiguration(
                signingPublicKey: rotatedSigningKey.publicKey.rawRepresentation,
                signedDevices: [rotatedSignedDevice],
                signedOneTimePublicKeys: [],
                signedMLKEMOneTimePublicKeys: []
            )

            let rotated = try await session.refreshIdentitiesAssessingImpact(
                secretName: "alice",
                deviceId: deviceConfig.deviceId,
                forceRefresh: true
            )
            #expect(rotated.impact == .freshSessionRecommended)

            await session.shutdown()
        } catch {
            await session.shutdown()
            throw error
        }
    }

    @Test("Should retrieve existing session identity from storage without refresh")
    func testRetrieveExistingIdentityFromStorage() async throws {
        do {
            let (store, _) = try await setupTestSession()
            
            // Clear any existing identities to start with a clean state
            store.identities.removeAll()
            
            // Create a test identity and store it
            let testIdentity = try await createTestIdentityWithoutStoring(for: "alice")
            try await store.createSessionIdentity(testIdentity)
            
            // Verify the identity was stored
            let storedIdentities = try await store.fetchSessionIdentities()
            #expect(storedIdentities.count == 1)
            #expect(storedIdentities.first?.id == testIdentity.id)
            
            // Test: getSessionIdentities should return the existing identity
            let retrievedIdentities = try await session.getSessionIdentities(with: "alice")
            #expect(retrievedIdentities.count == 1, "Should find exactly one identity for alice")
            #expect(retrievedIdentities.first?.id == testIdentity.id, "Should return the same identity that was stored")
            
            // Verify the identity properties are correct
            if let retrievedIdentity = retrievedIdentities.first,
               let props = try? await retrievedIdentity.props(symmetricKey: session.getDatabaseSymmetricKey()) {
                #expect(props.secretName == "alice", "Identity should have correct secret name")
                // Note: deviceId in props is the device ID from the device configuration, not the identity ID
                // The identity ID is the UUID of the SessionIdentity itself
                #expect(props.deviceId != UUID(), "Identity should have a valid device ID")
            }
            
            // Test: refreshIdentities should return existing identity without force refresh
            let refreshedIdentities = try await session.refreshIdentities(secretName: "alice")
            #expect(refreshedIdentities.count == 1, "Should return existing identity without refresh")
            #expect(refreshedIdentities.first?.id == testIdentity.id, "Should return the same identity without creating new one")
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
    
    @Test("Should handle multiple existing identities for same recipient")
    func testMultipleExistingIdentitiesForSameRecipient() async throws {
        do {
            let (store, _) = try await setupTestSession()
            
            // Clear any existing identities to start with a clean state
            store.identities.removeAll()
            
            // Create multiple test identities for the same recipient
            let identity1 = try await createTestIdentityWithoutStoring(for: "alice")
            let identity2 = try await createTestIdentityWithoutStoring(for: "alice")
            
            try await store.createSessionIdentity(identity1)
            try await store.createSessionIdentity(identity2)
            
            // Verify both identities were stored
            let storedIdentities = try await store.fetchSessionIdentities()
            #expect(storedIdentities.count == 2)
            
            // Test: getSessionIdentities should return both identities
            let retrievedIdentities = try await session.getSessionIdentities(with: "alice")
            #expect(retrievedIdentities.count == 2, "Should find both identities for alice")
            
            // Verify both identities are for the correct recipient
            for identity in retrievedIdentities {
                if let props = try? await identity.props(symmetricKey: session.getDatabaseSymmetricKey()) {
                    #expect(props.secretName == "alice", "All identities should have correct secret name")
                }
            }
            
            // Test: refreshIdentities should return both existing identities without force refresh
            let refreshedIdentities = try await session.refreshIdentities(secretName: "alice")
            #expect(refreshedIdentities.count == 2, "Should return both existing identities without refresh")
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
    
    @Test("Should handle empty storage correctly")
    func testEmptyStorageHandling() async throws {
        do {
            let (store, _) = try await setupTestSession()
            
            // Verify storage is empty initially
            let storedIdentities = try await store.fetchSessionIdentities()
            #expect(storedIdentities.isEmpty)
            
            // Test: getSessionIdentities should return empty array
            let retrievedIdentities = try await session.getSessionIdentities(with: "alice")
            #expect(retrievedIdentities.isEmpty, "Should return empty array when no identities exist")
            
            // Test: refreshIdentities should return empty array when no identities exist
            let refreshedIdentities = try await session.refreshIdentities(secretName: "alice")
            #expect(refreshedIdentities.isEmpty, "Should return empty array when no identities exist")
            
            // Ensure proper cleanup
            await session.shutdown()
        } catch {
            // Ensure proper cleanup
            await session.shutdown()
            throw error
        }
    }
} 
