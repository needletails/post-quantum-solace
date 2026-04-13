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

        session.isViable = true
        await store.setPublishableName(mockUserData.ssn)

        session = try await session.createSession(
            secretName: mockUserData.ssn,
            appPassword: mockUserData.sap
        ) {}

        await session.setAppPassword(mockUserData.sap)
        session = try await session.startSession(appPassword: mockUserData.sap)

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
            throw PQSSession.SessionErrors.invalidDeviceIdentity
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
            throw PQSSession.SessionErrors.invalidSignature
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
        let newCurveKey = Curve25519.KeyAgreement.PrivateKey()
        let mlKEMPrivateKey = try crypto.generateMLKem1024PrivateKey()
        let mlKEMPublicKey = try MLKEMPublicKey(
            id: UUID(),
            mlKEMPrivateKey.publicKey.rawRepresentation
        )
        guard let currentSignedDevice = context.activeUserConfiguration.signedDevices.first,
              var currentDevice = try? currentSignedDevice.verified(using: oldSigningKey) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }

        await currentDevice.updateSigningPublicKey(newSigningKey.publicKey.rawRepresentation)
        await currentDevice.updateLongTermPublicKey(newCurveKey.publicKey.rawRepresentation)
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
            throw PQSSession.SessionErrors.sessionNotInitialized
        }
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }

        let signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey
        )
        let signingPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: context.activeUserConfiguration.signingPublicKey
        )

        let updatedSignedDevices = try context.activeUserConfiguration.signedDevices.map { signed -> UserConfiguration.SignedDeviceConfiguration in
            guard let verified = try signed.verified(using: signingPublicKey) else {
                throw PQSSession.SessionErrors.invalidSignature
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
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encrypted)
    }
    
    private func createPeerIdentity(secretName: String, suffix: Int) async throws {
        let curve = crypto.generateCurve25519PrivateKey()
        let signing = crypto.generateCurve25519SigningPrivateKey()
        let mlkemPrivate = try crypto.generateMLKem1024PrivateKey()
        let mlkemPublic = try MLKEMPublicKey(id: UUID(), mlkemPrivate.publicKey.rawRepresentation)
        let deviceId = UUID()
        let device = UserDeviceConfiguration(
            deviceId: deviceId,
            signingPublicKey: signing.publicKey.rawRepresentation,
            longTermPublicKey: curve.publicKey.rawRepresentation,
            finalMLKEMPublicKey: mlkemPublic,
            deviceName: "peer-\(suffix)",
            hmacData: Data(repeating: UInt8(suffix + 1), count: 32),
            isMasterDevice: suffix == 0
        )
        _ = try await session.createEncryptableSessionIdentityModel(
            with: device,
            oneTimePublicKey: nil,
            mlKEMPublicKey: mlkemPublic,
            for: secretName,
            associatedWith: deviceId,
            new: Int.random(in: 1 ..< Int.max)
        )
    }
    
    private func makeReSignedConfiguration(
        from context: SessionContext,
        newSigningKey: Curve25519.Signing.PrivateKey
    ) throws -> UserConfiguration {
        let oldSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: context.activeUserConfiguration.signingPublicKey)
        let reSignedDevices = try context.activeUserConfiguration.signedDevices.map { signed in
            guard let verified = try signed.verified(using: oldSigningKey) else {
                throw PQSSession.SessionErrors.invalidSignature
            }
            return try UserConfiguration.SignedDeviceConfiguration(device: verified, signingKey: newSigningKey)
        }
        return UserConfiguration(
            signingPublicKey: newSigningKey.publicKey.rawRepresentation,
            signedDevices: reSignedDevices,
            signedOneTimePublicKeys: context.activeUserConfiguration.signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: context.activeUserConfiguration.signedMLKEMOneTimePublicKeys
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
        let originalCurveKey = originalContext.sessionUser.deviceKeys.longTermPrivateKey

        // Act
        try await session.rotateKeysOnPotentialCompromise()

        // Assert session context has new keys
        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }

        #expect(rotatedContext.sessionUser.deviceKeys.signingPrivateKey != originalSigningKey)
        #expect(rotatedContext.sessionUser.deviceKeys.longTermPrivateKey != originalCurveKey)
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
        let originalCurveIds = Set(
            originalContext.activeUserConfiguration.signedOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )
        let originalMLKEMIds = Set(
            originalContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )

        #expect(originalCurveIds.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(originalMLKEMIds.count == PQSSessionConstants.oneTimeKeyBatchSize)

        try await session.rotateKeysOnPotentialCompromise()

        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated session context should not be nil")
            return
        }

        let rotatedCurveIds = Set(
            rotatedContext.activeUserConfiguration.signedOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )
        let rotatedMLKEMIds = Set(
            rotatedContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
                .filter { $0.deviceId == deviceId }
                .map(\.id)
        )

        #expect(rotatedCurveIds.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(rotatedMLKEMIds.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(rotatedCurveIds.isDisjoint(with: originalCurveIds))
        #expect(rotatedMLKEMIds.isDisjoint(with: originalMLKEMIds))

        let verifiedCurveKeys = try rotatedContext.activeUserConfiguration.getVerifiedCurveKeys(deviceId: deviceId)
        let verifiedMLKEMKeys = try rotatedContext.activeUserConfiguration.getVerifiedMLKEMKeys(deviceId: deviceId)
        #expect(verifiedCurveKeys.count == PQSSessionConstants.oneTimeKeyBatchSize)
        #expect(verifiedMLKEMKeys.count == PQSSessionConstants.oneTimeKeyBatchSize)

        let remoteCurveIds = Set(
            try await store.fetchOneTimeKeyIdentities(
                for: secretName,
                deviceId: deviceId.uuidString,
                type: .curve
            )
        )
        let remoteMLKEMIds = Set(
            try await store.fetchOneTimeKeyIdentities(
                for: secretName,
                deviceId: deviceId.uuidString,
                type: .mlKEM
            )
        )
        #expect(remoteCurveIds == rotatedCurveIds)
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
        } catch let error as PQSSession.SessionErrors {
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
        } catch let error as PQSSession.SessionErrors {
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
        try await createPeerIdentity(secretName: peerSecret, suffix: 0)
        try await createPeerIdentity(secretName: peerSecret, suffix: 1)
        
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
    
    @Test("force refreshing self identities synchronizes active user configuration from transport")
    func testRefreshIdentitiesSelfForceRefreshSynchronizesActiveConfiguration() async throws {
        _ = try await setupRotatableSession()
        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        
        let newSigningKey = Curve25519.Signing.PrivateKey()
        let reSignedConfiguration = try makeReSignedConfiguration(from: originalContext, newSigningKey: newSigningKey)
        await store.setUserConfigurations(index: 0, config: reSignedConfiguration)
        
        let mySecret = originalContext.sessionUser.secretName
        _ = try await session.refreshIdentities(secretName: mySecret, forceRefresh: true)
        
        guard let refreshedContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }
        #expect(refreshedContext.activeUserConfiguration.signingPublicKey == newSigningKey.publicKey.rawRepresentation)
        
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

    @Test("rotateMLKEMKeysIfNeeded publishes batched allSignedDevices when local account has multiple devices")
    func testRotateMLKEMKeysIfNeeded_multiDeviceUsesBatchPayload() async throws {
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
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        // Persist through SessionCache so PQSSession.getSessionContext() sees the same blob (not stale in-memory cache).
        try await sessionCache.updateLocalSessionContext(encryptedMulti)

        let roundTripData = try await sessionCache.fetchLocalSessionContext()
        guard let roundTripPlain = try await crypto.decrypt(data: roundTripData, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionDecryptionError
        }
        let persistedContext = try BinaryDecoder().decode(SessionContext.self, from: roundTripPlain)
        #expect(persistedContext.activeUserConfiguration.signedDevices.count == 2)

        let serverConfiguration = context.activeUserConfiguration
        await store.setUserConfigurations(index: 0, config: serverConfiguration)

        let rotated = try await session.rotateMLKEMKeysIfNeeded()
        #expect(rotated == true)

        #expect(await transport.publishRotatedKeysCallCount == 1)
        let publishedKeys = await store.lastPublishedRotatedKeys
        #expect(publishedKeys?.allSignedDevices?.count == 2)

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
}

