//
//  KeyRotationTests.swift
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

import DoubleRatchetKit
import BinaryCodable
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing
import Crypto

private extension MessagePipeline {
    /// Production binds `session` inside the first ratchet job; tests that drive
    /// `updateOneTimeKey(remove:)` directly have no such job.
    func bindSessionForTesting(_ session: PQSSession) {
        self.session = session
    }
}

@Suite(.serialized)
actor KeyRotationTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    /// Sets up a basic session with a single device and cached context.
    private func setupRotatableSession() async throws -> (_MockTransportDelegate, MockIdentityStore) {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("rotationSalt")
        await session.setLogLevel(.trace)
        await session.setDatabaseDelegate(conformer: cacheStore)
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

        return (transport, cacheStore)
    }

    private func makeLinkedSignedDevice(from context: SessionContext) throws -> UserConfiguration.SignedDeviceConfiguration {
        let signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey
        )
        guard let currentSignedDevice = context.activeUserConfiguration.signedDevices.first,
              let currentDevice = try? currentSignedDevice.verified(
                using: Curve25519.Signing.PublicKey(rawRepresentation: context.activeUserConfiguration.signingPublicKey)
              ) else {
            throw PQSError.invalidDeviceIdentity
        }

        let linkedDevice = UserDeviceConfiguration(
            deviceId: UUID(),
            signingPublicKey: currentDevice.signingPublicKey,
            longTermPublicKey: currentDevice.longTermPublicKey,
            finalMLKEMPublicKey: currentDevice.finalMLKEMPublicKey,
            deviceName: "linked-device",
            hmacData: currentDevice.hmacData,
            isMasterDevice: false
        )
        return try UserConfiguration.SignedDeviceConfiguration(
            device: linkedDevice,
            signingKey: signingPrivateKey
        )
    }

    private func makeCorruptedSignedDevice(
        from signedDevice: UserConfiguration.SignedDeviceConfiguration
    ) throws -> UserConfiguration.SignedDeviceConfiguration {
        let signedDeviceJSON = try JSONEncoder().encode(signedDevice)
        guard var signedDeviceObject = try JSONSerialization.jsonObject(with: signedDeviceJSON) as? [String: Any] else {
            throw PQSError.invalidSignature
        }
        signedDeviceObject["c"] = Data(repeating: 0xA5, count: 64).base64EncodedString()
        return try JSONDecoder().decode(
            UserConfiguration.SignedDeviceConfiguration.self,
            from: try JSONSerialization.data(withJSONObject: signedDeviceObject)
        )
    }

    private func makeSingleDeviceCompromiseRotation(from context: SessionContext) async throws -> RotatedPublicKeys {
        let oldSigningKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: context.activeUserConfiguration.signingPublicKey
        )
        let newSigningKey = Curve25519.Signing.PrivateKey()
        let newX25519Key = Curve25519.KeyAgreement.PrivateKey()
        let mlKEMPrivateKey = try crypto.generateMLKem1024PrivateKey()
        let mlKEMPublicKey = try MLKEMPublicKey(
            id: UUID(),
            mlKEMPrivateKey.publicKey.rawRepresentation
        )
        guard let currentSignedDevice = context.activeUserConfiguration.signedDevices.first,
              var currentDevice = try? currentSignedDevice.verified(using: oldSigningKey) else {
            throw PQSError.invalidDeviceIdentity
        }

        await currentDevice.updateSigningPublicKey(newSigningKey.publicKey.rawRepresentation)
        await currentDevice.updateLongTermPublicKey(newX25519Key.publicKey.rawRepresentation)
        await currentDevice.updateFinalMLKEMPublicKey(mlKEMPublicKey)

        return try RotatedPublicKeys(
            pskData: newSigningKey.publicKey.rawRepresentation,
            signedDevice: UserConfiguration.SignedDeviceConfiguration(
                device: currentDevice,
                signingKey: newSigningKey
            )
        )
    }

    private func setCurrentDeviceMasterFlag(_ isMaster: Bool) async throws {
        guard var context = await session.sessionContext else {
            throw PQSError.sessionNotInitialized
        }
        guard let cache = await session.cache else {
            throw PQSError.databaseNotInitialized
        }

        let signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey
        )
        let signingPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: context.activeUserConfiguration.signingPublicKey
        )

        let updatedSignedDevices = try context.activeUserConfiguration.signedDevices.map { signed -> UserConfiguration.SignedDeviceConfiguration in
            guard let verified = try signed.verified(using: signingPublicKey) else {
                throw PQSError.invalidSignature
            }
            let updated = UserDeviceConfiguration(
                deviceId: verified.deviceId,
                signingPublicKey: verified.signingPublicKey,
                longTermPublicKey: verified.longTermPublicKey,
                finalMLKEMPublicKey: verified.finalMLKEMPublicKey,
                deviceName: verified.deviceName,
                hmacData: verified.hmacData,
                isMasterDevice: verified.deviceId == context.sessionUser.deviceId ? isMaster : verified.isMasterDevice,
                lastSeenAt: verified.lastSeenAt
            )
            return try UserConfiguration.SignedDeviceConfiguration(device: updated, signingKey: signingPrivateKey)
        }

        context.activeUserConfiguration = UserConfiguration(
            signingPublicKey: context.activeUserConfiguration.signingPublicKey,
            signedDevices: updatedSignedDevices,
            signedOneTimePublicKeys: context.activeUserConfiguration.signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: context.activeUserConfiguration.signedMLKEMOneTimePublicKeys
        )
        await session.setSessionContext(context)

        let encoded = try BinaryEncoder().encode(context)
        guard let encrypted = try await crypto.encrypt(data: encoded, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encrypted)
    }
    
    /// Creates a peer account with `deviceCount` devices. Publishes one account-signed
    /// `UserConfiguration` to the mock server (rotation fan-out resolves recipients from
    /// server-verified devices) and creates a matching local `SessionIdentity` per device
    /// so outbound encrypt lanes already exist.
    private func createPeerAccount(secretName: String, deviceCount: Int) async throws {
        let accountSigning = crypto.generateCurve25519SigningPrivateKey()
        var devices: [UserDeviceConfiguration] = []
        var signedDevices: [UserConfiguration.SignedDeviceConfiguration] = []
        for suffix in 0 ..< deviceCount {
            let x25519 = crypto.generateCurve25519PrivateKey()
            let deviceSigning = crypto.generateCurve25519SigningPrivateKey()
            let mlkemPrivate = try crypto.generateMLKem1024PrivateKey()
            let mlkemPublic = try MLKEMPublicKey(id: UUID(), mlkemPrivate.publicKey.rawRepresentation)
            let device = UserDeviceConfiguration(
                deviceId: UUID(),
                signingPublicKey: deviceSigning.publicKey.rawRepresentation,
                longTermPublicKey: x25519.publicKey.rawRepresentation,
                finalMLKEMPublicKey: mlkemPublic,
                deviceName: "peer-\(suffix)",
                hmacData: Data(repeating: UInt8(suffix + 1), count: 32),
                isMasterDevice: suffix == 0
            )
            devices.append(device)
            signedDevices.append(
                try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: accountSigning)
            )
        }
        let configuration = UserConfiguration(
            signingPublicKey: accountSigning.publicKey.rawRepresentation,
            signedDevices: signedDevices,
            signedOneTimePublicKeys: [],
            signedMLKEMOneTimePublicKeys: []
        )
        await store.upsertUserConfiguration(
            secretName: secretName,
            deviceId: devices[0].deviceId,
            config: configuration
        )
        for device in devices {
            _ = try await session.createEncryptableSessionIdentityModel(
                with: device,
                oneTimePublicKey: nil,
                mlKEMPublicKey: device.finalMLKEMPublicKey,
                for: secretName,
                associatedWith: device.deviceId,
                new: Int.random(in: 1 ..< Int.max)
            )
        }
    }
    
    private func makeReSignedConfiguration(
        from context: SessionContext,
        newSigningKey: Curve25519.Signing.PrivateKey
    ) throws -> UserConfiguration {
        let oldSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: context.activeUserConfiguration.signingPublicKey)
        let reSignedDevices = try context.activeUserConfiguration.signedDevices.map { signed in
            guard let verified = try signed.verified(using: oldSigningKey) else {
                throw PQSError.invalidSignature
            }
            return try UserConfiguration.SignedDeviceConfiguration(device: verified, signingKey: newSigningKey)
        }
        return UserConfiguration(
            signingPublicKey: newSigningKey.publicKey.rawRepresentation,
            signedDevices: reSignedDevices,
            signedOneTimePublicKeys: context.activeUserConfiguration.signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: context.activeUserConfiguration.signedMLKEMOneTimePublicKeys,
            signedDeviceKeyBundles: context.activeUserConfiguration.signedDeviceKeyBundles
        )
    }

    // MARK: - Tests

    @Test("rotateKeysOnPotentialCompromise should update signing, curve and MLKEM keys and publish rotation")
    func testRotateKeysOnPotentialCompromise() async throws {
        _ = try await setupRotatableSession()

        // Capture original key material
        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let originalSigningKey = originalContext.sessionUser.deviceKeys.signingPrivateKey
        let originalX25519Key = originalContext.sessionUser.deviceKeys.longTermPrivateKey

        // Act
        try await session.rotateKeysOnPotentialCompromise()

        // Assert session context has new keys
        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }

        #expect(rotatedContext.sessionUser.deviceKeys.signingPrivateKey != originalSigningKey)
        #expect(rotatedContext.sessionUser.deviceKeys.longTermPrivateKey != originalX25519Key)
        #expect(await session.keyLoadingState == .complete)

        // Assert that publishRotatedKeys was called by checking store user configuration was updated
        let userConfigs = await store.userConfigurations
        #expect(userConfigs.count == 1, "Expected a single user configuration in TransportStore after rotation")

        await session.shutdown()
    }

    @Test("rotateKeysOnPotentialCompromise replaces current-device one-time key batches")
    func testRotateKeysOnPotentialCompromise_replacesCurrentDeviceOneTimeKeys() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let deviceId = originalContext.sessionUser.deviceId
        let secretName = originalContext.sessionUser.secretName
        let originalX25519Ids = Set(
            originalContext.activeUserConfiguration.signedOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )
        let originalMLKEMIds = Set(
            originalContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )

        #expect(originalX25519Ids.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(originalMLKEMIds.count == PQSSessionConstants.oneTimeKeyBatchSize)

        try await session.rotateKeysOnPotentialCompromise()

        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }

        let rotatedX25519Ids = Set(
            rotatedContext.activeUserConfiguration.signedOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )
        let rotatedMLKEMIds = Set(
            rotatedContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )

        #expect(rotatedX25519Ids.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(rotatedMLKEMIds.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(rotatedX25519Ids.isDisjoint(with: originalX25519Ids))
        #expect(rotatedMLKEMIds.isDisjoint(with: originalMLKEMIds))

        let verifiedX25519Keys = try rotatedContext.activeUserConfiguration.getVerifiedX25519Keys(deviceId: deviceId)
        let verifiedMLKEMKeys = try rotatedContext.activeUserConfiguration.getVerifiedMLKEMKeys(deviceId: deviceId)
        #expect(verifiedX25519Keys.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(verifiedMLKEMKeys.count == PQSSessionConstants.oneTimeKeyBatchSize)

        let remoteX25519Ids = Set(
            try await store.fetchOneTimeKeyIdentities(
                for: secretName,
                deviceId: deviceId.uuidString,
                type: .x25519
            )
        )
        let remoteMLKEMIds = Set(
            try await store.fetchOneTimeKeyIdentities(
                for: secretName,
                deviceId: deviceId.uuidString,
                type: .mlKEM
            )
        )
        #expect(remoteX25519Ids == rotatedX25519Ids)
        #expect(remoteMLKEMIds == rotatedMLKEMIds)

        await session.shutdown()
    }

    @Test("rotateKeysOnPotentialCompromise refreshes stale local device list and publishes batched rotation")
    func testRotateKeysOnPotentialCompromise_refreshesStaleLocalMultiDeviceState() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        var serverConfiguration = originalContext.activeUserConfiguration
        let linkedSignedDevice = try makeLinkedSignedDevice(from: originalContext)
        serverConfiguration.signedDevices.append(linkedSignedDevice)
        await store.setUserConfigurations(index: 0, config: serverConfiguration)

        let localDeviceCountBeforeRotation = await session.sessionContext?.activeUserConfiguration.signedDevices.count
        #expect(localDeviceCountBeforeRotation == 1)

        let serverDeviceCountBeforeRotation = await store.userConfigurations.first?.config.signedDevices.count
        #expect(serverDeviceCountBeforeRotation == 2)

        try await session.rotateKeysOnPotentialCompromise()

        let publishedKeys = await store.lastPublishedRotatedKeys
        #expect(publishedKeys?.allSignedDevices?.count == 2)

        let publishedIds = Set(publishedKeys?.allSignedDevices?.map(\.id) ?? [])
        #expect(publishedIds.count == 2)
        #expect(publishedIds.contains(originalContext.sessionUser.deviceId))
        #expect(publishedIds.contains(linkedSignedDevice.id))

        let rotatedServerConfiguration = await store.userConfigurations.first?.config
        #expect(rotatedServerConfiguration?.signedDevices.count == 2)

        await session.shutdown()
    }

    @Test("rotateKeysOnPotentialCompromise recovers corrupted multi-device state by pruning invalid devices")
    func testRotateKeysOnPotentialCompromise_recoversCorruptedMultiDeviceState() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let linkedSignedDevice = try makeLinkedSignedDevice(from: originalContext)
        let corruptedLinkedSignedDevice = try makeCorruptedSignedDevice(from: linkedSignedDevice)
        var serverConfiguration = originalContext.activeUserConfiguration
        serverConfiguration.signedDevices.append(corruptedLinkedSignedDevice)
        await store.setUserConfigurations(index: 0, config: serverConfiguration)

        try await session.rotateKeysOnPotentialCompromise()

        let publishedKeys = await store.lastPublishedRotatedKeys
        #expect(publishedKeys?.allSignedDevices == nil)
        #expect(publishedKeys?.recovery?.recoveringDeviceId == originalContext.sessionUser.deviceId)
        #expect(publishedKeys?.recovery?.prunedDeviceIds == [linkedSignedDevice.id])

        let rotatedServerConfiguration = await store.userConfigurations.first?.config
        #expect(rotatedServerConfiguration?.signedDevices.count == 1)
        #expect(rotatedServerConfiguration?.signedDevices.first?.id == originalContext.sessionUser.deviceId)

        await session.shutdown()
    }

    @Test("rotateKeysOnPotentialCompromise fails fast when local signing key cannot verify own server device")
    func testRotateKeysOnPotentialCompromise_signingKeyOutOfSyncFailsFast() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let localSigningKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: originalContext.activeUserConfiguration.signingPublicKey
        )
        let divergentSigningKey = Curve25519.Signing.PrivateKey()
        var serverConfiguration = originalContext.activeUserConfiguration
        serverConfiguration.signingPublicKey = divergentSigningKey.publicKey.rawRepresentation
        serverConfiguration.signedDevices = try serverConfiguration.signedDevices.compactMap { signed in
            guard let device = try signed.verified(using: localSigningKey) else {
                return nil
            }
            return try UserConfiguration.SignedDeviceConfiguration(device: device, signingKey: divergentSigningKey)
        }
        await store.setUserConfigurations(index: 0, config: serverConfiguration)

        do {
            try await session.rotateKeysOnPotentialCompromise()
            Issue.record("Expected key rotation to fail when local signing key is out of sync")
        } catch let error as PQSError {
            #expect(error == .signingKeyOutOfSync)
        }

        let published = await store.lastPublishedRotatedKeys
        #expect(published == nil)

        await session.shutdown()
    }

    @Test("rotateKeysOnPotentialCompromise rejects non-master devices")
    func testRotateKeysOnPotentialCompromise_rejectsNonMasterDevice() async throws {
        _ = try await setupRotatableSession()
        try await setCurrentDeviceMasterFlag(false)

        do {
            try await session.rotateKeysOnPotentialCompromise()
            Issue.record("Expected key rotation to fail for non-master devices")
        } catch let error as PQSError {
            #expect(error == .compromiseRotationRequiresMasterDevice)
        }

        let published = await store.lastPublishedRotatedKeys
        #expect(published == nil)

        await session.shutdown()
    }

    @Test("rotateCurrentDeviceKeys rotates child device keys without account signing key rollover")
    func testRotateCurrentDeviceKeys_forNonMasterDevice() async throws {
        _ = try await setupRotatableSession()
        try await setCurrentDeviceMasterFlag(false)

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let originalSigningPrivateKey = originalContext.sessionUser.deviceKeys.signingPrivateKey
        let originalLongTermPrivateKey = originalContext.sessionUser.deviceKeys.longTermPrivateKey
        let originalFinalMLKEMId = originalContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id

        try await session.rotateCurrentDeviceKeys()

        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }

        #expect(rotatedContext.sessionUser.deviceKeys.signingPrivateKey == originalSigningPrivateKey)
        #expect(rotatedContext.sessionUser.deviceKeys.longTermPrivateKey != originalLongTermPrivateKey)
        #expect(rotatedContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id != originalFinalMLKEMId)
        #expect(rotatedContext.activeUserConfiguration.signingPublicKey == originalContext.activeUserConfiguration.signingPublicKey)
        #expect(await session.keyLoadingState == .complete)

        let publishedKeys = await store.lastPublishedRotatedKeys
        #expect(publishedKeys != nil)
        #expect(publishedKeys?.allSignedDevices == nil)
        #expect(publishedKeys?.deviceKeyBundle?.id == originalContext.sessionUser.deviceId)
        #expect(publishedKeys?.pskData == originalContext.activeUserConfiguration.signingPublicKey)

        await session.shutdown()
    }

    @Test("mock server rejects single-device compromise rotation when server configuration is multi-device")
    func testMockServerRejectsSingleDeviceCompromiseRotationForMultiDeviceConfig() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        var serverConfiguration = originalContext.activeUserConfiguration
        serverConfiguration.signedDevices.append(try makeLinkedSignedDevice(from: originalContext))
        await store.setUserConfigurations(index: 0, config: serverConfiguration)

        let invalidSingleDeviceRotation = try await makeSingleDeviceCompromiseRotation(from: originalContext)

        do {
            try await store.publishRotatedKeys(
                for: originalContext.sessionUser.secretName,
                deviceId: originalContext.sessionUser.deviceId.uuidString,
                rotated: invalidSingleDeviceRotation
            )
            Issue.record("Expected mock server to reject single-device multi-device compromise rotation")
        } catch let error as TestError {
            #expect(error == .multiDeviceRotationRequiresBatch)
        }

        await session.shutdown()
    }
    
    @Test("rotation reestablishment sends one nickname control frame per contact secret and still fans out per device")
    func testRotationReestablishmentDedupesNicknameSendsPerContact() async throws {
        let (transport, _) = try await setupRotatableSession()
        let peerSecret = "dedupe-peer"
        try await createPeerAccount(secretName: peerSecret, deviceCount: 2)
        
        let stream = AsyncStream<ReceivedMessage> { continuation in
            transport.continuation = continuation
        }
        let collector = Task { () -> [ReceivedMessage] in
            var collected: [ReceivedMessage] = []
            for await received in stream {
                collected.append(received)
                if collected.count >= 6 {
                    break
                }
            }
            return collected
        }
        
        try await session.rotateCurrentDeviceKeys()
        try await Task.sleep(nanoseconds: 500_000_000)
        transport.continuation?.finish()
        let collected = await collector.value
        
        let peerReestablishment = collected.filter { received in
            guard received.recipient == peerSecret else { return false }
            guard let event = received.transportEvent else { return false }
            if case .sessionReestablishment = event {
                return true
            }
            return false
        }
        #expect(peerReestablishment.count == 2, "Expected one nickname send deduped by secretName with per-device fan-out (2 devices)")
        
        await session.shutdown()
    }
    
    @Test("force refreshing self identities rejects unauthenticated account signing-key replacement")
    func testRefreshIdentitiesSelfForceRefreshRejectsForeignAccountSigningKey() async throws {
        _ = try await setupRotatableSession()
        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        
        let newSigningKey = Curve25519.Signing.PrivateKey()
        let reSignedConfiguration = try makeReSignedConfiguration(from: originalContext, newSigningKey: newSigningKey)
        await store.setUserConfigurations(index: 0, config: reSignedConfiguration)
        
        let mySecret = originalContext.sessionUser.secretName
        await #expect(throws: PQSError.signingKeyOutOfSync) {
            _ = try await session.refreshIdentities(secretName: mySecret, forceRefresh: true)
        }
        
        guard let refreshedContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        #expect(refreshedContext.activeUserConfiguration.signingPublicKey == originalContext.activeUserConfiguration.signingPublicKey)
        
        await session.shutdown()
    }

    @Test("rotateMLKEMKeysIfNeeded should not rotate when within interval")
    func testRotateMLKEMKeysIfNeeded_noRotationWhenFresh() async throws {
        _ = try await setupRotatableSession()

        // Ensure rotateKeysDate is now so rotation is not needed
        guard await session.sessionContext != nil else {
            Issue.record("Session context should be initialized")
            return
        }

        if var context = await session.sessionContext {
            context.sessionUser.deviceKeys.rotateKeysDate = Date()
            await session.setSessionContext(context)
        }

        let rotated = try await session.rotateMLKEMKeysIfNeeded()
        #expect(rotated == false)

        await session.shutdown()
    }

    @Test("rotateMLKEMKeysIfNeeded should rotate when past interval and update rotateKeysDate")
    func testRotateMLKEMKeysIfNeeded_rotatesWhenDue() async throws {
        _ = try await setupRotatableSession()

        let pastDate = Calendar.current.date(byAdding: .day, value: -(PQSSessionConstants.keyRotationIntervalDays + 1), to: Date())!

        if var context = await session.sessionContext {
            context.sessionUser.deviceKeys.rotateKeysDate = pastDate
            await session.setSessionContext(context)
        }

        let rotated = try await session.rotateMLKEMKeysIfNeeded()
        #expect(rotated == true)

        guard let newContext = await session.sessionContext else {
            Issue.record("New session context should not be nil")
            return
        }

        let rotatedDate = newContext.sessionUser.deviceKeys.rotateKeysDate
        #expect(rotatedDate != nil)
        if let rotatedDate {
            #expect(rotatedDate > pastDate)
        }

        await session.shutdown()
    }

    @Test("rotateMLKEMKeysIfNeeded publishes device-signed bundle when local account has multiple devices")
    func testRotateMLKEMKeysIfNeeded_multiDeviceUsesDeviceBundlePayload() async throws {
        await store.resetLastPublishedRotatedKeys()
        let (transport, _) = try await setupRotatableSession()

        guard let sessionCache = await session.cache else {
            Issue.record("Session cache should be initialized")
            return
        }

        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let linkedSignedDevice = try makeLinkedSignedDevice(from: context)
        context.activeUserConfiguration.signedDevices.append(linkedSignedDevice)

        let pastDate = Calendar.current.date(byAdding: .day, value: -(PQSSessionConstants.keyRotationIntervalDays + 1), to: Date())!
        context.sessionUser.deviceKeys.rotateKeysDate = pastDate

        await session.setSessionContext(context)
        let encodedMulti = try BinaryEncoder().encode(context)
        guard let encryptedMulti = try await crypto.encrypt(data: encodedMulti, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }
        // Persist through SessionCache so PQSSession.getSessionContext() sees the same blob (not stale in-memory cache).
        try await sessionCache.updateLocalSessionContext(encryptedMulti)

        let roundTripData = try await sessionCache.fetchLocalSessionContext()
        guard let roundTripPlain = try await crypto.decrypt(data: roundTripData, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }
        let persistedContext = try BinaryDecoder().decode(SessionContext.self, from: roundTripPlain)
        #expect(persistedContext.activeUserConfiguration.signedDevices.count == 2)

        let serverConfiguration = context.activeUserConfiguration
        await store.setUserConfigurations(index: 0, config: serverConfiguration)

        let rotated = try await session.rotateMLKEMKeysIfNeeded()
        #expect(rotated == true)

        #expect(await transport.publishRotatedKeysCallCount == 1)
        let publishedKeys = await store.lastPublishedRotatedKeys
        #expect(publishedKeys?.allSignedDevices == nil)
        #expect(publishedKeys?.deviceKeyBundle?.id == context.sessionUser.deviceId)

        await session.shutdown()
    }

    @Test("refreshOneTimeKeys with MLKEM type should replace MLKEM one-time key batch")
    func testRefreshOneTimeKeysMLKEMReplacesKeyBatch() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let originalIds = Set(
            originalContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.map(\.id)
        )
        #expect(!originalIds.isEmpty)

        try await store.batchDeleteOneTimeKeys(
            for: originalContext.sessionUser.secretName,
            with: originalContext.sessionUser.deviceId.uuidString,
            type: .mlKEM
        )
        try await session.refreshOneTimeKeys(refreshType: .mlKEM)

        guard let updatedContext = await session.sessionContext else {
            Issue.record("Updated session context should not be nil")
            return
        }

        let updatedIds = Set(
            updatedContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys.map(\.id)
        )

        #expect(updatedIds.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(updatedIds != originalIds)

        await session.shutdown()
    }

    @Test("adoptVerifiedUserConfiguration keeps the local device-signed bundle over a stale snapshot and republishes it")
    func testAdoptVerifiedUserConfiguration_preservesRotatedLocalBundleAndRepublishes() async throws {
        await store.resetLastPublishedRotatedKeys()
        let (transport, _) = try await setupRotatableSession()

        guard let preRotationContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        // Snapshot the server/peer-visible configuration *before* rotation. This is what a
        // lookup cache, a read-after-publish race, or a sibling's full republish hands back.
        let staleSnapshot = preRotationContext.activeUserConfiguration
        let staleBundle = staleSnapshot.signedDeviceKeyBundles.first {
            $0.id == preRotationContext.sessionUser.deviceId
        }
        #expect(staleBundle != nil)

        try await session.rotateCurrentDeviceKeys()
        let publishesAfterRotation = await transport.publishRotatedKeysCallCount

        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }
        let rotatedPrivateId = rotatedContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id
        #expect(rotatedPrivateId != preRotationContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id)

        // Adopt the stale snapshot exactly as `refreshUserConfiguration` does on registration.
        try await session.adoptVerifiedUserConfiguration(staleSnapshot)

        guard let adoptedContext = await session.sessionContext else {
            Issue.record("Adopted session context should not be nil")
            return
        }
        let deviceSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: adoptedContext.sessionUser.deviceKeys.signingPrivateKey
        ).publicKey
        let adoptedSelfBundles = adoptedContext.activeUserConfiguration.signedDeviceKeyBundles.filter {
            $0.id == adoptedContext.sessionUser.deviceId
        }
        #expect(adoptedSelfBundles.count == 1)
        let adoptedSelfBundle = try adoptedSelfBundles.first?.verified(using: deviceSigningKey)
        // The advertised final ML-KEM key must be the one this device can actually open.
        #expect(adoptedSelfBundle?.finalMLKEMPublicKey.id == rotatedPrivateId)
        #expect(adoptedContext.sessionUser.deviceKeys.finalMLKEMPrivateKey.id == rotatedPrivateId)

        // Drift on the snapshot is the event that converges the server record.
        #expect(await transport.publishRotatedKeysCallCount == publishesAfterRotation + 1)
        let republished = await store.lastPublishedRotatedKeys?.deviceKeyBundle
        #expect(republished?.id == adoptedContext.sessionUser.deviceId)
        let republishedBundle = try republished?.verified(using: deviceSigningKey)
        #expect(republishedBundle?.finalMLKEMPublicKey.id == rotatedPrivateId)

        // A snapshot that already matches must not publish again.
        try await session.adoptVerifiedUserConfiguration(adoptedContext.activeUserConfiguration)
        #expect(await transport.publishRotatedKeysCallCount == publishesAfterRotation + 1)

        await session.shutdown()
    }

    @Test("routine rotation retains exactly one prior final ML-KEM key and persists it")
    func testRoutineRotation_retainsOnePriorFinalMLKEMKey() async throws {
        _ = try await setupRotatableSession()

        guard let generation0 = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Session context should be initialized")
            return
        }
        #expect(generation0.previousFinalMLKEMPrivateKey == nil)

        try await session.rotateCurrentDeviceKeys()
        guard let generation1 = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Rotated session context should not be nil")
            return
        }
        // The retired key is retained byte-for-byte: a box sealed to generation 0's
        // public key opens with it.
        #expect(generation1.finalMLKEMPrivateKey.id != generation0.finalMLKEMPrivateKey.id)
        #expect(generation1.previousFinalMLKEMPrivateKey == generation0.finalMLKEMPrivateKey)
        #expect(generation1.finalMLKEMPrivateKey(matching: generation0.finalMLKEMPrivateKey.id) == generation0.finalMLKEMPrivateKey)
        #expect(generation1.finalMLKEMPrivateKey(matching: generation1.finalMLKEMPrivateKey.id) == generation1.finalMLKEMPrivateKey)

        // Persisted, not just in-memory: reload the encrypted context from the cache.
        guard let sessionCache = await session.cache else {
            Issue.record("Session cache should be initialized")
            return
        }
        let persistedData = try await sessionCache.fetchLocalSessionContext()
        guard let persistedPlain = try await crypto.decrypt(data: persistedData, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }
        let persisted = try BinaryDecoder().decode(SessionContext.self, from: persistedPlain)
        #expect(persisted.sessionUser.deviceKeys.previousFinalMLKEMPrivateKey == generation0.finalMLKEMPrivateKey)

        // A second rotation slides the window: generation 0 is released, only
        // generation 1 is retained.
        try await session.rotateCurrentDeviceKeys()
        guard let generation2 = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Second rotated session context should not be nil")
            return
        }
        #expect(generation2.previousFinalMLKEMPrivateKey == generation1.finalMLKEMPrivateKey)
        #expect(generation2.finalMLKEMPrivateKey(matching: generation0.finalMLKEMPrivateKey.id) == nil)

        await session.shutdown()
    }

    @Test("compromise rotation discards the retained prior final ML-KEM key")
    func testCompromiseRotation_clearsPriorFinalMLKEMKey() async throws {
        _ = try await setupRotatableSession()

        try await session.rotateCurrentDeviceKeys()
        guard let afterRoutine = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Rotated session context should not be nil")
            return
        }
        #expect(afterRoutine.previousFinalMLKEMPrivateKey != nil)

        try await session.rotateKeysOnPotentialCompromise()
        guard let afterCompromise = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Compromise-rotated session context should not be nil")
            return
        }
        #expect(afterCompromise.finalMLKEMPrivateKey.id != afterRoutine.finalMLKEMPrivateKey.id)
        #expect(afterCompromise.previousFinalMLKEMPrivateKey == nil)
        #expect(afterCompromise.finalMLKEMPrivateKey(matching: afterRoutine.finalMLKEMPrivateKey.id) == nil)

        await session.shutdown()
    }

    @Test("DeviceKeys without a prior final ML-KEM key decodes and re-encodes byte-identically")
    func testDeviceKeys_priorFinalKeyIsOptionalOnTheWire() async throws {
        _ = try await setupRotatableSession()
        guard let keys = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Session context should be initialized")
            return
        }
        #expect(keys.previousFinalMLKEMPrivateKey == nil)

        let encoded = try BinaryEncoder().encode(keys)
        let decoded = try BinaryDecoder().decode(DeviceKeys.self, from: encoded)
        #expect(decoded == keys)
        #expect(try BinaryEncoder().encode(decoded) == encoded)

        var rotated = keys
        let replacement = try MLKEMPrivateKey(id: UUID(), crypto.generateMLKem1024PrivateKey().encode())
        rotated.replaceFinalMLKEMPrivateKey(replacement, retainingPrevious: true)
        let rotatedRoundTrip = try BinaryDecoder().decode(DeviceKeys.self, from: BinaryEncoder().encode(rotated))
        #expect(rotatedRoundTrip.previousFinalMLKEMPrivateKey == keys.finalMLKEMPrivateKey)
        #expect(rotatedRoundTrip.finalMLKEMPrivateKey == replacement)

        await session.shutdown()
    }

    @Test("routine rotation leaves the dedicated sealed-sender key unchanged")
    func testRoutineRotation_doesNotRotateDedicatedSealedSenderKey() async throws {
        _ = try await setupRotatableSession()
        guard let before = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Session context should be initialized")
            return
        }
        #expect(before.sealedSenderMLKEMPrivateKey != nil)
        let dedicatedId = before.sealedSenderMLKEMPrivateKey?.id

        try await session.rotateCurrentDeviceKeys()
        guard let after = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Rotated session context should not be nil")
            return
        }
        #expect(after.sealedSenderMLKEMPrivateKey?.id == dedicatedId)
        #expect(after.previousSealedSenderMLKEMPrivateKey == nil)
        #expect(after.finalMLKEMPrivateKey.id != before.finalMLKEMPrivateKey.id)

        await session.shutdown()
    }

    @Test("compromise rotation replaces the dedicated sealed-sender key and clears retention")
    func testCompromiseRotation_replacesDedicatedSealedSenderKey() async throws {
        _ = try await setupRotatableSession()
        try await session.rotateSealedSenderMLKEMKey()
        guard let afterSettings = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Settings-rotated keys should exist")
            return
        }
        #expect(afterSettings.previousSealedSenderMLKEMPrivateKey != nil)
        let previousDedicated = afterSettings.sealedSenderMLKEMPrivateKey?.id

        try await session.rotateKeysOnPotentialCompromise()
        guard let afterCompromise = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Compromise-rotated keys should exist")
            return
        }
        #expect(afterCompromise.sealedSenderMLKEMPrivateKey?.id != previousDedicated)
        #expect(afterCompromise.previousSealedSenderMLKEMPrivateKey == nil)

        await session.shutdown()
    }

    @Test("publishLocalDeviceKeyBundle publishes exactly once")
    func testPublishLocalDeviceKeyBundle_publishesOnce() async throws {
        await store.resetLastPublishedRotatedKeys()
        let (transport, _) = try await setupRotatableSession()
        let before = await transport.publishRotatedKeysCallCount
        try await session.publishLocalDeviceKeyBundle()
        #expect(await transport.publishRotatedKeysCallCount == before + 1)
        try await session.publishLocalDeviceKeyBundle()
        #expect(await transport.publishRotatedKeysCallCount == before + 2)

        await session.shutdown()
    }

    @Test("schema mint derives bundle public keys from held private keys")
    func testMintLocalDeviceKeyBundle_derivesFromPrivateKeys() async throws {
        _ = try await setupRotatableSession()
        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        context.activeUserConfiguration.signedDeviceKeyBundles.removeAll()
        let minted = try await session.mintLocalDeviceKeyBundleIfNeeded(context)
        let deviceId = minted.sessionUser.deviceId
        let signingKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: minted.sessionUser.deviceKeys.signingPrivateKey
        ).publicKey
        let bundle = try minted.activeUserConfiguration.signedDeviceKeyBundles
            .first { $0.id == deviceId }?
            .verified(using: signingKey)
        let expectedLongTerm = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: minted.sessionUser.deviceKeys.longTermPrivateKey
        ).publicKey.rawRepresentation
        #expect(bundle?.longTermPublicKey == expectedLongTerm)
        #expect(bundle?.finalMLKEMPublicKey.id == minted.sessionUser.deviceKeys.finalMLKEMPrivateKey.id)
        #expect(bundle?.updatedAt != nil)

        await session.shutdown()
    }

    @Test("DeviceKeyBundleMerge prefers newer updatedAt and treats nil as oldest")
    func testDeviceKeyBundleMerge_updatedAtRule() {
        let now = Date()
        let earlier = now.addingTimeInterval(-60)
        #expect(DeviceKeyBundleMerge.shouldPreferIncoming(existingUpdatedAt: nil, incomingUpdatedAt: now))
        #expect(!DeviceKeyBundleMerge.shouldPreferIncoming(existingUpdatedAt: now, incomingUpdatedAt: nil))
        #expect(DeviceKeyBundleMerge.shouldPreferIncoming(existingUpdatedAt: earlier, incomingUpdatedAt: now))
        #expect(!DeviceKeyBundleMerge.shouldPreferIncoming(existingUpdatedAt: now, incomingUpdatedAt: earlier))
        #expect(DeviceKeyBundleMerge.shouldPreferIncoming(existingUpdatedAt: now, incomingUpdatedAt: now))
        #expect(DeviceKeyBundleMerge.shouldPreferIncoming(existingUpdatedAt: nil, incomingUpdatedAt: nil))
    }

    @Test("DeviceKeyBundle without a dedicated public key re-encodes byte-identically")
    func testDeviceKeyBundle_dedicatedFieldSkippedWhenNil() throws {
        let kem = try crypto.generateMLKem1024PrivateKey()
        let publicKey = try MLKEMPublicKey(id: UUID(), kem.publicKey.rawRepresentation)
        let bundle = UserConfiguration.DeviceKeyBundle(
            deviceId: UUID(),
            longTermPublicKey: Data(repeating: 3, count: 32),
            finalMLKEMPublicKey: publicKey,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            capabilities: .sealedSender
        )
        #expect(bundle.sealedSenderMLKEMPublicKey == nil)
        let encoded = try BinaryEncoder().encode(bundle)
        let decoded = try BinaryDecoder().decode(UserConfiguration.DeviceKeyBundle.self, from: encoded)
        #expect(try BinaryEncoder().encode(decoded) == encoded)
        #expect(decoded.sealedSenderMLKEMPublicKey == nil)
        #expect(DeviceCapabilities.dedicatedSealedKey.rawValue == 1 << 1)
    }

    @Test("adoption keeps the sibling bundle with the greater updatedAt")
    func testAdoption_keepsNewerSiblingBundle() async throws {
        _ = try await setupRotatableSession()
        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let accountSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey)
        let siblingSigning = Curve25519.Signing.PrivateKey()
        let siblingId = UUID()
        let kem = try crypto.generateMLKem1024PrivateKey()
        let olderPublic = try MLKEMPublicKey(id: UUID(), kem.publicKey.rawRepresentation)
        let newerPublic = try MLKEMPublicKey(id: UUID(), kem.publicKey.rawRepresentation)
        let siblingDevice = UserDeviceConfiguration(
            deviceId: siblingId,
            signingPublicKey: siblingSigning.publicKey.rawRepresentation,
            longTermPublicKey: Data(repeating: 7, count: 32),
            finalMLKEMPublicKey: olderPublic,
            deviceName: "sibling",
            hmacData: Data(repeating: 8, count: 32),
            isMasterDevice: false)
        let signedSibling = try UserConfiguration.SignedDeviceConfiguration(
            device: siblingDevice,
            signingKey: accountSigning)
        let olderBundle = try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: siblingId,
                longTermPublicKey: siblingDevice.longTermPublicKey,
                finalMLKEMPublicKey: olderPublic,
                updatedAt: Date(timeIntervalSince1970: 100)),
            signingKey: siblingSigning)
        let newerBundle = try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: siblingId,
                longTermPublicKey: siblingDevice.longTermPublicKey,
                finalMLKEMPublicKey: newerPublic,
                updatedAt: Date(timeIntervalSince1970: 200)),
            signingKey: siblingSigning)

        context.activeUserConfiguration.signedDevices.append(signedSibling)
        context.activeUserConfiguration.signedDeviceKeyBundles.append(newerBundle)
        var incoming = context.activeUserConfiguration
        incoming.signedDeviceKeyBundles.removeAll { $0.id == siblingId }
        incoming.signedDeviceKeyBundles.append(olderBundle)

        let merged = await session.userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
            incoming,
            currentContext: context)
        let kept = try merged.signedDeviceKeyBundles
            .first { $0.id == siblingId }?
            .verified(using: siblingSigning.publicKey)
        #expect(kept?.finalMLKEMPublicKey.id == newerPublic.id)

        await session.shutdown()
    }

    @Test("verifyPublishedDeviceKeyBundle looks up once per unknown key id")
    func testVerifyPublishedDeviceKeyBundle_oncePerKeyId() async throws {
        let (transport, _) = try await setupRotatableSession()
        await transport.resetCallTracking()
        let unknown = UUID()
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: unknown)
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: unknown)
        #expect(await transport.findConfigurationCallCount == 1)
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: UUID())
        #expect(await transport.findConfigurationCallCount == 2)

        await session.shutdown()
    }

    /// Signs a bundle for the local device that keeps its long-term and final keys but
    /// advertises `dedicated` as the sealed-sender key — the shape a server row takes when
    /// the device once published a dedicated key it no longer holds.
    private func makeSelfBundle(
        from context: SessionContext,
        dedicated: MLKEMPublicKey?
    ) throws -> UserConfiguration.SignedDeviceKeyBundle {
        let deviceId = context.sessionUser.deviceId
        let deviceSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey)
        let current = try #require(
            try context.activeUserConfiguration.signedDeviceKeyBundles
                .first { $0.id == deviceId }?
                .verified(using: deviceSigning.publicKey))
        var capabilities: DeviceCapabilities = .sealedSender
        if dedicated != nil {
            capabilities.insert(.dedicatedSealedKey)
        }
        return try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: deviceId,
                longTermPublicKey: current.longTermPublicKey,
                finalMLKEMPublicKey: current.finalMLKEMPublicKey,
                updatedAt: Date(),
                capabilities: capabilities,
                sealedSenderMLKEMPublicKey: dedicated),
            signingKey: deviceSigning)
    }

    private func makeForeignDedicatedKey() throws -> MLKEMPublicKey {
        let kem = try crypto.generateMLKem1024PrivateKey()
        return try MLKEMPublicKey(id: UUID(), kem.publicKey.rawRepresentation)
    }

    @Test("server bundle advertising a dedicated key this device does not hold triggers a republish")
    func testDedicatedKeyDrift_republishesHeldKeys() async throws {
        await store.resetLastPublishedRotatedKeys()
        let (transport, _) = try await setupRotatableSession()
        guard let context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let deviceKeys = context.sessionUser.deviceKeys
        let heldDedicatedId = try #require(deviceKeys.sealedSenderMLKEMPrivateKey?.id)
        let deviceSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: deviceKeys.signingPrivateKey).publicKey

        // Same long-term and final keys as ours, so the pre-fix comparison sees no drift.
        let foreign = try makeForeignDedicatedKey()
        var remote = try await store.findConfiguration(for: context.sessionUser.secretName)
        remote.signedDeviceKeyBundles.removeAll { $0.id == context.sessionUser.deviceId }
        remote.signedDeviceKeyBundles.append(try makeSelfBundle(from: context, dedicated: foreign))

        let before = await transport.publishRotatedKeysCallCount
        let converged = await session.republishLocalDeviceKeyBundleIfRemoteDrifted(
            incoming: remote,
            currentContext: context,
            triggerUnknownRecipientKeyId: foreign.id)
        #expect(converged)
        #expect(await transport.publishRotatedKeysCallCount == before + 1)
        let published = try await store.lastPublishedRotatedKeys?.deviceKeyBundle?
            .verified(using: deviceSigning)
        #expect(published?.sealedSenderMLKEMPublicKey?.id == heldDedicatedId)
        #expect(published?.finalMLKEMPublicKey.id == deviceKeys.finalMLKEMPrivateKey.id)
        #expect(published?.capabilities.contains(.dedicatedSealedKey) == true)

        await session.shutdown()
    }

    @Test("server bundle missing our minted dedicated key triggers a republish")
    func testUnadvertisedDedicatedKey_republishesHeldKeys() async throws {
        let (transport, _) = try await setupRotatableSession()
        guard let context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        // The offline-unlock mint path: local holds a dedicated key the server never saw.
        var remote = try await store.findConfiguration(for: context.sessionUser.secretName)
        remote.signedDeviceKeyBundles.removeAll { $0.id == context.sessionUser.deviceId }
        remote.signedDeviceKeyBundles.append(try makeSelfBundle(from: context, dedicated: nil))

        let before = await transport.publishRotatedKeysCallCount
        let converged = await session.republishLocalDeviceKeyBundleIfRemoteDrifted(
            incoming: remote,
            currentContext: context)
        #expect(converged)
        #expect(await transport.publishRotatedKeysCallCount == before + 1)

        await session.shutdown()
    }

    @Test("server bundle matching the held keys does not republish and reports converged")
    func testMatchingServerBundle_doesNotRepublish() async throws {
        let (transport, _) = try await setupRotatableSession()
        guard let context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let remote = try await store.findConfiguration(for: context.sessionUser.secretName)
        let before = await transport.publishRotatedKeysCallCount
        let converged = await session.republishLocalDeviceKeyBundleIfRemoteDrifted(
            incoming: remote,
            currentContext: context,
            triggerUnknownRecipientKeyId: UUID())
        #expect(converged)
        #expect(await transport.publishRotatedKeysCallCount == before)

        await session.shutdown()
    }

    @Test("local authority rebuilds the bundle when the stored copy advertises a dedicated key we do not hold")
    func testLocalAuthoritativeBundle_rebuildsFromHeldPrivateKeys() async throws {
        _ = try await setupRotatableSession()
        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let deviceKeys = context.sessionUser.deviceKeys
        let deviceId = context.sessionUser.deviceId
        let heldDedicatedId = try #require(deviceKeys.sealedSenderMLKEMPrivateKey?.id)
        let deviceSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: deviceKeys.signingPrivateKey).publicKey

        // Consistent stored copy is returned as-is.
        let stored = try #require(context.activeUserConfiguration.signedDeviceKeyBundles.first { $0.id == deviceId })
        let unchanged = await session.localAuthoritativeDeviceKeyBundle(in: context, deviceSigningKey: deviceSigning)
        #expect(unchanged?.data == stored.data)

        // A stored copy carrying someone else's dedicated key (e.g. adopted from a stale
        // server snapshot) is replaced by one signed from the keys actually held.
        let foreign = try makeForeignDedicatedKey()
        let stale = try makeSelfBundle(from: context, dedicated: foreign)
        context.activeUserConfiguration.signedDeviceKeyBundles.removeAll { $0.id == deviceId }
        context.activeUserConfiguration.signedDeviceKeyBundles.append(stale)

        let rebuilt = try #require(
            await session.localAuthoritativeDeviceKeyBundle(in: context, deviceSigningKey: deviceSigning))
        let bundle = try #require(try rebuilt.verified(using: deviceSigning))
        #expect(bundle.sealedSenderMLKEMPublicKey?.id == heldDedicatedId)
        #expect(bundle.finalMLKEMPublicKey.id == deviceKeys.finalMLKEMPrivateKey.id)
        #expect(bundle.capabilities.contains(.dedicatedSealedKey))

        // Adoption of that stale snapshot therefore carries the held keys, not the foreign one.
        var incoming = context.activeUserConfiguration
        incoming.signedDeviceKeyBundles.removeAll { $0.id == deviceId }
        incoming.signedDeviceKeyBundles.append(stale)
        let merged = await session.userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
            incoming,
            currentContext: context)
        let adopted = try merged.signedDeviceKeyBundles
            .first { $0.id == deviceId }?
            .verified(using: deviceSigning)
        #expect(adopted?.sealedSenderMLKEMPublicKey?.id == heldDedicatedId)

        await session.shutdown()
    }

    @Test("a failed heal lookup releases the key id so the next unknown-key event retries")
    func testVerifyPublishedDeviceKeyBundle_retriesAfterLookupFailure() async throws {
        let (transport, _) = try await setupRotatableSession()
        await transport.resetCallTracking()
        let unknown = UUID()

        transport.findConfigurationError = PQSError.userNotFound
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: unknown)
        #expect(await transport.findConfigurationCallCount == 1)

        transport.findConfigurationError = nil
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: unknown)
        #expect(await transport.findConfigurationCallCount == 2)

        // Converged now; the same id is suppressed for the rest of the session.
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: unknown)
        #expect(await transport.findConfigurationCallCount == 2)

        await session.shutdown()
    }

    @Test("a rejected republish releases the key id and the next unknown-key event converges the server")
    func testVerifyPublishedDeviceKeyBundle_retriesAfterPublishFailure() async throws {
        await store.resetLastPublishedRotatedKeys()
        let (transport, _) = try await setupRotatableSession()
        guard let context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let secretName = context.sessionUser.secretName
        let deviceId = context.sessionUser.deviceId
        let heldDedicatedId = try #require(context.sessionUser.deviceKeys.sealedSenderMLKEMPrivateKey?.id)
        let deviceSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey).publicKey

        // Server row drifted to a dedicated key we never held.
        let foreign = try makeForeignDedicatedKey()
        var drifted = try await store.findConfiguration(for: secretName)
        drifted.signedDeviceKeyBundles.removeAll { $0.id == deviceId }
        drifted.signedDeviceKeyBundles.append(try makeSelfBundle(from: context, dedicated: foreign))
        await store.upsertUserConfiguration(secretName: secretName, deviceId: deviceId, config: drifted)
        await transport.resetCallTracking()

        transport.publishRotatedKeysError = PQSError.transportNotInitialized
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: foreign.id)
        #expect(await transport.findConfigurationCallCount == 1)
        #expect(await store.lastPublishedRotatedKeys == nil)

        transport.publishRotatedKeysError = nil
        await session.verifyPublishedDeviceKeyBundle(unknownRecipientKeyId: foreign.id)
        #expect(await transport.findConfigurationCallCount == 2)
        let published = try await store.lastPublishedRotatedKeys?.deviceKeyBundle?
            .verified(using: deviceSigning)
        #expect(published?.sealedSenderMLKEMPublicKey?.id == heldDedicatedId)

        // The server row now advertises the held key.
        let serverBundle = try await store.findConfiguration(for: secretName).signedDeviceKeyBundles
            .first { $0.id == deviceId }?
            .verified(using: deviceSigning)
        #expect(serverBundle?.sealedSenderMLKEMPublicKey?.id == heldDedicatedId)

        await session.shutdown()
    }

    /// Parks the first upload until the test opens the gate, and exposes
    /// `entered == 2` as the event that both tasks have reached the transport.
    private actor UploadGate {
        private var parked: CheckedContinuation<Void, Never>?
        private var secondEntered: CheckedContinuation<Void, Never>?
        private var isOpen = false
        private(set) var entries = 0

        func enter() -> Int {
            entries += 1
            if entries >= 2, let secondEntered {
                self.secondEntered = nil
                secondEntered.resume()
            }
            return entries
        }

        func waitUntilBothEntered() async {
            if entries >= 2 { return }
            await withCheckedContinuation { secondEntered = $0 }
        }

        func park() async {
            guard !isOpen else { return }
            await withCheckedContinuation { parked = $0 }
        }

        func open() {
            isOpen = true
            parked?.resume()
            parked = nil
        }
    }

    /// Dogfood 2026-09-15 (Device3 09:45:29): two ratchet handshakes consumed one-time
    /// keys in the same second; the replacement upload that finished first popped the
    /// FIFO and cancelled its still-in-flight sibling's PUT. The sibling's replacement
    /// key was never published. A completing upload may retire only itself.
    @Test("a fast one-time-key replacement does not cancel a slower sibling upload")
    func testConcurrentOneTimeKeyReplacements_doNotCancelEachOther() async throws {
        let (transport, _) = try await setupRotatableSession()
        guard let context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let spent = Array(context.activeUserConfiguration.signedOneTimePublicKeys.prefix(2))
        try #require(spent.count == 2)
        await transport.resetCallTracking()
        transport.rejectCancelledOneTimeKeyUploads = true

        let gate = UploadGate()
        transport.beforeUpdateOneTimeKeys = {
            // The first consumption's PUT is slow; the second completes immediately.
            if await gate.enter() == 1 { await gate.park() }
        }

        let pipeline = await session.messagePipeline
        // In production the ratchet job that consumed the key has already bound the
        // pipeline to its session; there is no handshake in this test, so bind it here.
        await pipeline.bindSessionForTesting(session)
        await pipeline.updateOneTimeKey(remove: spent[0].id)
        await pipeline.updateOneTimeKey(remove: spent[1].id)
        try #require(await pipeline.updateKeyTasks.count == 2)

        // Both tasks have reached the transport; one is parked, the other can
        // finish and retire. Wait for that retirement — callCount ticks before
        // the task drops itself from the dictionary.
        await gate.waitUntilBothEntered()
        var spins = 0
        while await pipeline.updateKeyTasks.count != 1 && spins < 2_000 {
            await Task.yield()
            spins += 1
        }

        #expect(await pipeline.updateKeyTasks.count == 1,
                "The slow upload must remain tracked after its sibling completes")
        #expect(await transport.updateOneTimeKeysCallCount == 1)

        let remaining = Array(await pipeline.updateKeyTasks.values)
        await gate.open()
        for handle in remaining {
            await handle.value
        }
        #expect(await pipeline.updateKeyTasks.isEmpty)
        #expect(await transport.updateOneTimeKeysCallCount == 2,
                "Both replacement keys must reach the server")
        // Both deltas must survive in the live context: neither task may write back a
        // pre-upload snapshot that resurrects the other's spent key or drops the other's
        // freshly minted private key.
        let finalContext = try #require(await session.sessionContext)
        let published = Set(finalContext.activeUserConfiguration.signedOneTimePublicKeys.map(\.id))
        #expect(!published.contains(spent[0].id))
        #expect(!published.contains(spent[1].id))
        let uploaded = Set(await transport.updateOneTimeKeysCalls.map(\.keyCount))
        #expect(uploaded == [1])
        let heldPrivateIds = Set(finalContext.sessionUser.deviceKeys.oneTimePrivateKeys.map(\.id))
        let publishedNew = published.subtracting(context.activeUserConfiguration.signedOneTimePublicKeys.map(\.id))
        #expect(publishedNew.count == 2, "Two replacement public keys must be advertised")
        #expect(publishedNew.isSubset(of: heldPrivateIds),
                "Every advertised replacement must have its private key held locally")

        await session.shutdown()
    }

    @Test("child linkDevice publishes its first bundle exactly once")
    func testChildLinkDevice_publishesFirstBundleOnce() async throws {
        _ = try await setupRotatableSession()
        guard let masterContext = await session.sessionContext else {
            Issue.record("Master session context should be initialized")
            return
        }

        var childSession = PQSSession()
        let childUserData = MockUserData(session: childSession)
        let childCache = MockIdentityStore(
            mockUserData: childUserData,
            session: childSession,
            isSender: true)
        let childTransport = _MockTransportDelegate(session: childSession, store: store)
        let linkDelegate = MockDeviceLinkingDelegate(secretName: masterContext.sessionUser.secretName)
        await childCache.setLocalSalt("childLinkSalt")
        await childSession.setDatabaseDelegate(conformer: childCache)
        await childSession.setTransportDelegate(conformer: childTransport)
        await childSession.setPQSSessionDelegate(conformer: SessionDelegate(session: childSession))
        await childSession.setReceiverDelegate(conformer: ReceiverDelegate(session: childSession))
        await childSession.setConnectivity(true)
        childSession.linkDelegate = linkDelegate

        let bundle = try await childSession.createDeviceCryptographicBundle(isMaster: false)
        guard let childDevice = try bundle.userConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == bundle.deviceKeys.deviceId
        }) else {
            Issue.record("Child bundle should include its device")
            return
        }
        let masterSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: masterContext.sessionUser.deviceKeys.signingPrivateKey)
        var configuration = masterContext.activeUserConfiguration
        configuration.signedDevices.removeAll { $0.id == childDevice.deviceId }
        configuration.signedDevices.append(try UserConfiguration.SignedDeviceConfiguration(
            device: childDevice,
            signingKey: masterSigning))
        for signedBundle in bundle.userConfiguration.signedDeviceKeyBundles {
            configuration.signedDeviceKeyBundles.removeAll { $0.id == signedBundle.id }
            configuration.signedDeviceKeyBundles.append(signedBundle)
        }
        for key in bundle.userConfiguration.signedOneTimePublicKeys {
            configuration.signedOneTimePublicKeys.removeAll { $0.id == key.id }
            configuration.signedOneTimePublicKeys.append(key)
        }
        for key in bundle.userConfiguration.signedMLKEMOneTimePublicKeys {
            configuration.signedMLKEMOneTimePublicKeys.removeAll { $0.id == key.id }
            configuration.signedMLKEMOneTimePublicKeys.append(key)
        }
        linkDelegate.userConfiguration = configuration
        await store.upsertUserConfiguration(
            secretName: masterContext.sessionUser.secretName,
            deviceId: bundle.deviceKeys.deviceId,
            config: configuration)

        await store.resetLastPublishedRotatedKeys()
        let before = await childTransport.publishRotatedKeysCallCount
        childSession = try await childSession.linkDevice(bundle: bundle, password: "123")
        #expect(await childTransport.publishRotatedKeysCallCount == before + 1)
        #expect(await store.lastPublishedRotatedKeys?.deviceKeyBundle?.id == bundle.deviceKeys.deviceId)
        let childSigning = try Curve25519.Signing.PrivateKey(
            rawRepresentation: bundle.deviceKeys.signingPrivateKey
        ).publicKey
        let publishedBundle = try await store.lastPublishedRotatedKeys?.deviceKeyBundle?
            .verified(using: childSigning)
        #expect(publishedBundle?.deviceId == bundle.deviceKeys.deviceId)
        #expect(publishedBundle?.sealedSenderMLKEMPublicKey != nil)

        await childSession.shutdown()
        await session.shutdown()
    }

    @Test("child linkDevice source publishes the first bundle before unlock")
    func testChildLinkDevice_sourcePublishesBeforeUnlock() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/PQSSession/Session/PQSSession+DeviceLinking.swift"),
            encoding: .utf8)
        #expect(source.contains("if !bundle.deviceConfiguration.isMasterDevice"))
        let publish = try #require(source.range(of: "try await publishLocalDeviceKeyBundle()"))
        let unlock = try #require(source.range(of: "return try await unlock(appPassword: credentials.password)"))
        #expect(publish.lowerBound < unlock.lowerBound)
    }

    @Test("schema mint of a dedicated sealed-sender key publishes once")
    func testMintSealedSenderKey_publishesOnce() async throws {
        let (transport, _) = try await setupRotatableSession()
        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        let keys = context.sessionUser.deviceKeys
        context.sessionUser.deviceKeys = DeviceKeys(
            deviceId: keys.deviceId,
            signingPrivateKey: keys.signingPrivateKey,
            longTermPrivateKey: keys.longTermPrivateKey,
            oneTimePrivateKeys: keys.oneTimePrivateKeys,
            mlKEMOneTimePrivateKeys: keys.mlKEMOneTimePrivateKeys,
            finalMLKEMPrivateKey: keys.finalMLKEMPrivateKey,
            rotateKeysDate: keys.rotateKeysDate)
        let minted: Bool
        (context, minted) = try await session.mintSealedSenderKeyIfNeeded(context)
        #expect(minted)
        await session.setSessionContext(context)
        let before = await transport.publishRotatedKeysCallCount
        try await session.publishLocalDeviceKeyBundle()
        #expect(await transport.publishRotatedKeysCallCount == before + 1)
        #expect(context.sessionUser.deviceKeys.sealedSenderMLKEMPrivateKey != nil)

        await session.shutdown()
    }

    @Test("envelope sealed to the final key opens after routine rotation")
    func testSpooledSealedEnvelopeOpensAfterRoutineRotation() async throws {
        _ = try await setupRotatableSession()
        guard let before = await session.sessionContext?.sessionUser.deviceKeys,
              let context = await session.sessionContext
        else {
            Issue.record("Session context should be initialized")
            return
        }
        let raw = try before.finalMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
        let finalPublic = try MLKEMPublicKey(
            id: before.finalMLKEMPrivateKey.id,
            raw.publicKey.rawRepresentation)
        let envelopeId = "env-seal-rotate"
        let packetId = "pkt-seal-rotate"
        let sealed = try makeSealedBox(
            to: finalPublic,
            recipientSecretName: context.sessionUser.secretName,
            recipientDeviceId: before.deviceId,
            envelopeId: envelopeId,
            packetId: packetId)

        try await session.rotateCurrentDeviceKeys()
        guard let after = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Rotated keys should exist")
            return
        }
        #expect(after.finalMLKEMPrivateKey.id != before.finalMLKEMPrivateKey.id)
        #expect(after.previousFinalMLKEMPrivateKey?.id == before.finalMLKEMPrivateKey.id)
        _ = try SealedInboundOpen.open(
            sealed,
            deviceKeys: after,
            recipientSecretName: context.sessionUser.secretName,
            recipientDeviceId: after.deviceId,
            envelopeId: envelopeId,
            packetId: packetId)

        await session.shutdown()
    }

    @Test("envelope sealed to the dedicated key still opens after final-key rotation")
    func testDedicatedSealedEnvelopeSurvivesFinalKeyRotation() async throws {
        _ = try await setupRotatableSession()
        guard let before = await session.sessionContext?.sessionUser.deviceKeys,
              let context = await session.sessionContext,
              let dedicatedPublic = try before.sealedSenderMLKEMPublicKey()
        else {
            Issue.record("Dedicated sealed-sender key should exist")
            return
        }
        let envelopeId = "env-dedicated"
        let packetId = "pkt-dedicated"
        let sealed = try makeSealedBox(
            to: dedicatedPublic,
            recipientSecretName: context.sessionUser.secretName,
            recipientDeviceId: before.deviceId,
            envelopeId: envelopeId,
            packetId: packetId)
        #expect(sealed.recipientKeyId == dedicatedPublic.id)

        try await session.rotateCurrentDeviceKeys()
        guard let after = await session.sessionContext?.sessionUser.deviceKeys else {
            Issue.record("Rotated keys should exist")
            return
        }
        #expect(after.sealedSenderMLKEMPrivateKey?.id == before.sealedSenderMLKEMPrivateKey?.id)
        _ = try SealedInboundOpen.open(
            sealed,
            deviceKeys: after,
            recipientSecretName: context.sessionUser.secretName,
            recipientDeviceId: after.deviceId,
            envelopeId: envelopeId,
            packetId: packetId)

        await session.shutdown()
    }

    private func makeSealedBox(
        to publicKey: MLKEMPublicKey,
        recipientSecretName: String,
        recipientDeviceId: UUID,
        envelopeId: String,
        packetId: String
    ) throws -> SealedOuterCiphertext {
        let certificate = try SenderCertificate.issue(
            secretName: "peer",
            deviceId: UUID(),
            issuedAt: Date(timeIntervalSince1970: 1_800_000_000),
            signingKey: try MLDSA65.PrivateKey()
        )
        let innerKEM = try MLKEM1024.PrivateKey()
        let signedMessage = try SignedRatchetMessage(
            message: RatchetMessage(
                header: EncryptedHeader(
                    remoteLongTermPublicKey: Data(repeating: 0xA7, count: 32),
                    remoteOneTimePublicKey: nil,
                    remoteMLKEMPublicKey: try MLKEMPublicKey(
                        innerKEM.publicKey.rawRepresentation
                    ),
                    headerCiphertext: Data(repeating: 0xB8, count: 48),
                    messageCiphertext: Data(repeating: 0xC9, count: 48),
                    oneTimeKeyId: nil,
                    mlKEMOneTimeKeyId: UUID(),
                    encrypted: Data(repeating: 0xDA, count: 48)
                ),
                ciphertext: Data("spooled sealed".utf8)
            ),
            signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation
        )
        return try SealedOuterBox.seal(
            certificate: certificate,
            signedMessage: signedMessage,
            recipientFinalMLKEMPublicKey: publicKey,
            recipientSecretName: recipientSecretName,
            recipientDeviceId: recipientDeviceId,
            envelopeId: envelopeId,
            packetId: packetId
        )
    }
}
