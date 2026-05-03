//
//  PerDeviceIdentityTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2026-04-17.
//
//  Copyright (c) 2026 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import BinaryCodable
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
@testable import PQSSession
import SessionEvents
import SessionModels
import Testing

/// Per-device identity invariants.
///
/// Each `DeviceID` owns a per-device signing keypair generated locally during link, and that
/// keypair is immutable for the lifetime of the device. Master compromise rotation rolls only
/// the account-level signing key (used to sign each `SignedDeviceConfiguration`) and re-signs
/// existing per-device entries — it never replaces a child's per-device public key. Child
/// devices that receive a `LinkedDeviceReprovisioningBundle` adopt the new account public key
/// only; their `signingPrivateKey` is never touched.
@Suite(.serialized)
actor PerDeviceIdentityTests {

    let crypto = NeedleTailCrypto()
    let store = TransportStore()
    var session = PQSSession()

    // MARK: - Helpers

    private func setupRotatableSession() async throws -> (_MockTransportDelegate, MockIdentityStore) {
        let mockUserData = MockUserData(session: session)
        let cacheStore = MockIdentityStore(mockUserData: mockUserData, session: session, isSender: true)
        let transport = _MockTransportDelegate(session: session, store: store)

        await cacheStore.setLocalSalt("perDeviceIdentitySalt")
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

    /// Builds a `SignedDeviceConfiguration` for a fresh linked device with its OWN unique
    /// per-device signing key (i.e. the correct shape). Wrapper signature uses the
    /// account-level signing key.
    private func makeUniqueLinkedSignedDevice(
        accountSigningKey: Curve25519.Signing.PrivateKey,
        currentDeviceTemplate: UserDeviceConfiguration
    ) throws -> (signed: UserConfiguration.SignedDeviceConfiguration, devicePerDeviceSigningPublicKey: Data) {
        let perDeviceSigningKey = Curve25519.Signing.PrivateKey()
        let linkedDevice = UserDeviceConfiguration(
            deviceId: UUID(),
            signingPublicKey: perDeviceSigningKey.publicKey.rawRepresentation,
            longTermPublicKey: currentDeviceTemplate.longTermPublicKey,
            finalMLKEMPublicKey: currentDeviceTemplate.finalMLKEMPublicKey,
            deviceName: "linked-device-\(UUID().uuidString.prefix(6))",
            hmacData: currentDeviceTemplate.hmacData,
            isMasterDevice: false
        )
        let signed = try UserConfiguration.SignedDeviceConfiguration(
            device: linkedDevice,
            signingKey: accountSigningKey
        )
        return (signed, perDeviceSigningKey.publicKey.rawRepresentation)
    }

    private func currentDevice(from context: SessionContext) throws -> UserDeviceConfiguration {
        let accountKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: context.activeUserConfiguration.signingPublicKey
        )
        guard let signedSelf = context.activeUserConfiguration.signedDevices.first(where: {
            $0.id == context.sessionUser.deviceId
        }), let device = try signedSelf.verified(using: accountKey) else {
            throw PQSSession.SessionErrors.invalidDeviceIdentity
        }
        return device
    }

    private func persist(context: SessionContext) async throws {
        guard let cache = await session.cache else {
            throw PQSSession.SessionErrors.databaseNotInitialized
        }
        await session.setSessionContext(context)
        let encoded = try BinaryEncoder().encode(context)
        guard let encrypted = try await crypto.encrypt(data: encoded, symmetricKey: session.getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encrypted)
    }

    // MARK: - Tests

    @Test("Per-device signing keys are unique across linked devices")
    func perDeviceKeysAreUniqueAcrossLinkedDevices() async throws {
        _ = try await setupRotatableSession()

        guard let originalContext = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let masterDevice = try currentDevice(from: originalContext)
        let accountSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: originalContext.sessionUser.deviceKeys.signingPrivateKey
        )

        let firstChild = try makeUniqueLinkedSignedDevice(
            accountSigningKey: accountSigningKey,
            currentDeviceTemplate: masterDevice
        )
        let secondChild = try makeUniqueLinkedSignedDevice(
            accountSigningKey: accountSigningKey,
            currentDeviceTemplate: masterDevice
        )

        var configWithTwoChildren = originalContext.activeUserConfiguration
        configWithTwoChildren.signedDevices.append(firstChild.signed)
        configWithTwoChildren.signedDevices.append(secondChild.signed)

        let accountPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: configWithTwoChildren.signingPublicKey
        )

        var perDeviceKeys: [UUID: Data] = [:]
        for signed in configWithTwoChildren.signedDevices {
            guard let verified = try signed.verified(using: accountPublicKey) else {
                Issue.record("Signed device \(signed.id) failed account-key verification")
                return
            }
            perDeviceKeys[verified.deviceId] = verified.signingPublicKey
        }

        #expect(perDeviceKeys.count == 3, "Expected master + two unique children")
        let uniquePerDevicePublicKeys = Set(perDeviceKeys.values)
        #expect(uniquePerDevicePublicKeys.count == perDeviceKeys.count,
               "Each device must own a distinct per-device signing public key")

        await session.shutdown()
    }

    @Test("installLinkedDeviceReprovisioningBundle preserves the receiving device's signingPrivateKey")
    func reprovisioningPreservesChildSigningKey() async throws {
        _ = try await setupRotatableSession()

        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        // Reshape the test session into a "child" by:
        //   - generating a brand-new master keypair (account)
        //   - generating a fresh per-device key for this device (replacing the bootstrap one)
        //   - rebuilding signedDevices: master (account), self (child)
        // We then capture this device's signingPrivateKey BEFORE reprovisioning.
        let masterAccountKey = Curve25519.Signing.PrivateKey()
        let newChildPerDeviceKey = Curve25519.Signing.PrivateKey()

        let masterDeviceId = UUID()
        let masterDevice = UserDeviceConfiguration(
            deviceId: masterDeviceId,
            signingPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation,
            longTermPublicKey: try currentDevice(from: context).longTermPublicKey,
            finalMLKEMPublicKey: try currentDevice(from: context).finalMLKEMPublicKey,
            deviceName: "master-device",
            hmacData: try currentDevice(from: context).hmacData,
            isMasterDevice: true
        )
        let signedMaster = try UserConfiguration.SignedDeviceConfiguration(
            device: masterDevice,
            signingKey: masterAccountKey
        )

        let selfDeviceTemplate = try currentDevice(from: context)
        let selfChildDevice = UserDeviceConfiguration(
            deviceId: selfDeviceTemplate.deviceId,
            signingPublicKey: newChildPerDeviceKey.publicKey.rawRepresentation,
            longTermPublicKey: selfDeviceTemplate.longTermPublicKey,
            finalMLKEMPublicKey: selfDeviceTemplate.finalMLKEMPublicKey,
            deviceName: "child-device",
            hmacData: selfDeviceTemplate.hmacData,
            isMasterDevice: false
        )
        let signedSelf = try UserConfiguration.SignedDeviceConfiguration(
            device: selfChildDevice,
            signingKey: masterAccountKey
        )

        let initialChildConfig = UserConfiguration(
            signingPublicKey: masterAccountKey.publicKey.rawRepresentation,
            signedDevices: [signedMaster, signedSelf],
            signedOneTimePublicKeys: [],
            signedMLKEMOneTimePublicKeys: []
        )

        // Replace this device's local signingPrivateKey to match its per-device entry.
        // Reuse the regular DeviceKeys init (the only post-init writer is the master-only
        // rotateAccountSigningKey, which we are explicitly NOT exercising here).
        let originalDeviceKeys = context.sessionUser.deviceKeys
        context.sessionUser.deviceKeys = DeviceKeys(
            deviceId: originalDeviceKeys.deviceId,
            signingPrivateKey: newChildPerDeviceKey.rawRepresentation,
            longTermPrivateKey: originalDeviceKeys.longTermPrivateKey,
            oneTimePrivateKeys: originalDeviceKeys.oneTimePrivateKeys,
            mlKEMOneTimePrivateKeys: originalDeviceKeys.mlKEMOneTimePrivateKeys,
            finalMLKEMPrivateKey: originalDeviceKeys.finalMLKEMPrivateKey,
            rotateKeysDate: originalDeviceKeys.rotateKeysDate
        )
        context.activeUserConfiguration = initialChildConfig
        try await persist(context: context)

        let childKeyBytesBefore = newChildPerDeviceKey.rawRepresentation

        // Master rotates the account key and re-signs the device list, preserving each
        // entry's inner signingPublicKey byte-for-byte.
        let rotatedMasterAccountKey = Curve25519.Signing.PrivateKey()
        let oldAccountPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: initialChildConfig.signingPublicKey
        )
        var rotatedDevices: [UserConfiguration.SignedDeviceConfiguration] = []
        for signed in initialChildConfig.signedDevices {
            guard let verified = try signed.verified(using: oldAccountPublicKey) else {
                Issue.record("Pre-rotation device \(signed.id) failed verification")
                return
            }
            rotatedDevices.append(try UserConfiguration.SignedDeviceConfiguration(
                device: verified,
                signingKey: rotatedMasterAccountKey
            ))
        }
        let rotatedConfig = UserConfiguration(
            signingPublicKey: rotatedMasterAccountKey.publicKey.rawRepresentation,
            signedDevices: rotatedDevices,
            signedOneTimePublicKeys: initialChildConfig.signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: initialChildConfig.signedMLKEMOneTimePublicKeys
        )

        let bundle = LinkedDeviceReprovisioningBundle(
            activeUserConfiguration: rotatedConfig,
            issuedByDeviceId: masterDeviceId,
            issuedAt: Date(),
            targetDeviceId: selfDeviceTemplate.deviceId
        )

        try await session.installLinkedDeviceReprovisioningBundle(bundle)

        guard let postContext = await session.sessionContext else {
            Issue.record("Session context should be available after install")
            return
        }

        #expect(postContext.sessionUser.deviceKeys.signingPrivateKey == childKeyBytesBefore,
               "Child's per-device signingPrivateKey must be byte-for-byte preserved after reprovisioning")
        #expect(postContext.activeUserConfiguration.signingPublicKey == rotatedMasterAccountKey.publicKey.rawRepresentation,
               "activeUserConfiguration must adopt the new account-level signing public key")

        await session.shutdown()
    }

    @Test("Linked child rotates device-owned key bundle without account signing key")
    func linkedChildRotatesDeviceOwnedBundle() async throws {
        _ = try await setupRotatableSession()

        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let masterAccountKey = Curve25519.Signing.PrivateKey()
        let childDeviceSigningKey = Curve25519.Signing.PrivateKey()
        let template = try currentDevice(from: context)

        let masterDevice = UserDeviceConfiguration(
            deviceId: UUID(),
            signingPublicKey: masterAccountKey.publicKey.rawRepresentation,
            longTermPublicKey: template.longTermPublicKey,
            finalMLKEMPublicKey: template.finalMLKEMPublicKey,
            deviceName: "master-device",
            hmacData: template.hmacData,
            isMasterDevice: true
        )
        let childDevice = UserDeviceConfiguration(
            deviceId: context.sessionUser.deviceId,
            signingPublicKey: childDeviceSigningKey.publicKey.rawRepresentation,
            longTermPublicKey: template.longTermPublicKey,
            finalMLKEMPublicKey: template.finalMLKEMPublicKey,
            deviceName: "child-device",
            hmacData: template.hmacData,
            isMasterDevice: false
        )
        let signedMaster = try UserConfiguration.SignedDeviceConfiguration(
            device: masterDevice,
            signingKey: masterAccountKey
        )
        let signedChild = try UserConfiguration.SignedDeviceConfiguration(
            device: childDevice,
            signingKey: masterAccountKey
        )
        let initialChildBundle = try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: childDevice.deviceId,
                longTermPublicKey: childDevice.longTermPublicKey,
                finalMLKEMPublicKey: childDevice.finalMLKEMPublicKey
            ),
            signingKey: childDeviceSigningKey
        )

        let originalDeviceKeys = context.sessionUser.deviceKeys
        context.sessionUser.deviceKeys = DeviceKeys(
            deviceId: originalDeviceKeys.deviceId,
            signingPrivateKey: childDeviceSigningKey.rawRepresentation,
            longTermPrivateKey: originalDeviceKeys.longTermPrivateKey,
            oneTimePrivateKeys: originalDeviceKeys.oneTimePrivateKeys,
            mlKEMOneTimePrivateKeys: originalDeviceKeys.mlKEMOneTimePrivateKeys,
            finalMLKEMPrivateKey: originalDeviceKeys.finalMLKEMPrivateKey,
            rotateKeysDate: originalDeviceKeys.rotateKeysDate
        )
        context.activeUserConfiguration = UserConfiguration(
            signingPublicKey: masterAccountKey.publicKey.rawRepresentation,
            signedDevices: [signedMaster, signedChild],
            signedOneTimePublicKeys: [],
            signedMLKEMOneTimePublicKeys: [],
            signedDeviceKeyBundles: [initialChildBundle]
        )
        try await persist(context: context)
        await store.setUserConfigurations(index: 0, config: context.activeUserConfiguration)

        let oldLongTermPrivateKey = context.sessionUser.deviceKeys.longTermPrivateKey
        try await session.rotateCurrentDeviceKeys()

        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated context should be available")
            return
        }

        #expect(rotatedContext.sessionUser.deviceKeys.signingPrivateKey == childDeviceSigningKey.rawRepresentation)
        #expect(rotatedContext.sessionUser.deviceKeys.longTermPrivateKey != oldLongTermPrivateKey)
        #expect(rotatedContext.activeUserConfiguration.signingPublicKey == masterAccountKey.publicKey.rawRepresentation)
        #expect(rotatedContext.activeUserConfiguration.signedDevices.map(\.id) == [signedMaster.id, signedChild.id])

        let published = await store.lastPublishedRotatedKeys
        #expect(published?.allSignedDevices == nil)
        #expect(published?.deviceKeyBundle?.id == childDevice.deviceId)
        #expect(published?.pskData == masterAccountKey.publicKey.rawRepresentation)

        let serverConfig = try await store.findUserConfiguration(secretName: context.sessionUser.secretName)
        let accountSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: serverConfig.signingPublicKey)
        guard let serverChild = try serverConfig.signedDevices.first(where: { $0.id == childDevice.deviceId })?
            .verified(using: accountSigningPublicKey) else {
            Issue.record("Server child membership should still verify under account key")
            return
        }
        #expect(serverChild.signingPublicKey == childDeviceSigningKey.publicKey.rawRepresentation)

        let childSigningPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: childDeviceSigningKey.publicKey.rawRepresentation)
        guard let rotatedBundle = try serverConfig.signedDeviceKeyBundles.first(where: { $0.id == childDevice.deviceId })?
            .verified(using: childSigningPublicKey) else {
            Issue.record("Server should store child-signed current key bundle")
            return
        }
        #expect(rotatedBundle.longTermPublicKey != childDevice.longTermPublicKey)

        await session.shutdown()
    }

    @Test("installLinkedDeviceReprovisioningBundle rejects bundles that re-attest us with a foreign per-device key")
    func reprovisioningRejectsForeignPerDeviceKey() async throws {
        _ = try await setupRotatableSession()

        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let masterAccountKey = Curve25519.Signing.PrivateKey()
        let realChildPerDeviceKey = Curve25519.Signing.PrivateKey()
        let foreignPerDeviceKey = Curve25519.Signing.PrivateKey()

        let selfDeviceTemplate = try currentDevice(from: context)

        // Local state is consistent with the REAL per-device key.
        let originalDeviceKeys = context.sessionUser.deviceKeys
        context.sessionUser.deviceKeys = DeviceKeys(
            deviceId: originalDeviceKeys.deviceId,
            signingPrivateKey: realChildPerDeviceKey.rawRepresentation,
            longTermPrivateKey: originalDeviceKeys.longTermPrivateKey,
            oneTimePrivateKeys: originalDeviceKeys.oneTimePrivateKeys,
            mlKEMOneTimePrivateKeys: originalDeviceKeys.mlKEMOneTimePrivateKeys,
            finalMLKEMPrivateKey: originalDeviceKeys.finalMLKEMPrivateKey,
            rotateKeysDate: originalDeviceKeys.rotateKeysDate
        )

        // Build a malicious / buggy bundle whose entry for our DeviceID carries a DIFFERENT
        // signing public key than the one we hold privately. This is exactly the corruption
        // shape the old `signingPrivateKey = bundle.signingPrivateKeyData` overwrite produced.
        let foreignChildDevice = UserDeviceConfiguration(
            deviceId: selfDeviceTemplate.deviceId,
            signingPublicKey: foreignPerDeviceKey.publicKey.rawRepresentation,
            longTermPublicKey: selfDeviceTemplate.longTermPublicKey,
            finalMLKEMPublicKey: selfDeviceTemplate.finalMLKEMPublicKey,
            deviceName: selfDeviceTemplate.deviceName,
            hmacData: selfDeviceTemplate.hmacData,
            isMasterDevice: false
        )
        let signedForeign = try UserConfiguration.SignedDeviceConfiguration(
            device: foreignChildDevice,
            signingKey: masterAccountKey
        )

        let badConfig = UserConfiguration(
            signingPublicKey: masterAccountKey.publicKey.rawRepresentation,
            signedDevices: [signedForeign],
            signedOneTimePublicKeys: [],
            signedMLKEMOneTimePublicKeys: []
        )
        context.activeUserConfiguration = UserConfiguration(
            signingPublicKey: context.activeUserConfiguration.signingPublicKey,
            signedDevices: context.activeUserConfiguration.signedDevices,
            signedOneTimePublicKeys: context.activeUserConfiguration.signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: context.activeUserConfiguration.signedMLKEMOneTimePublicKeys
        )
        try await persist(context: context)

        let bundle = LinkedDeviceReprovisioningBundle(
            activeUserConfiguration: badConfig,
            issuedByDeviceId: UUID(),
            issuedAt: Date(),
            targetDeviceId: selfDeviceTemplate.deviceId
        )

        do {
            try await session.installLinkedDeviceReprovisioningBundle(bundle)
            Issue.record("Expected install to throw deviceIdentityCorrupted for foreign-key bundle")
        } catch let error as PQSSession.SessionErrors {
            #expect(error == .deviceIdentityCorrupted,
                   "Foreign-key bundles must surface as .deviceIdentityCorrupted; got \(error)")
        }

        // Local key must remain untouched on rejection.
        guard let postContext = await session.sessionContext else {
            Issue.record("Session context should be available after rejection")
            return
        }
        #expect(postContext.sessionUser.deviceKeys.signingPrivateKey == realChildPerDeviceKey.rawRepresentation,
               "A rejected reprovisioning bundle must not mutate local signing key")

        await session.shutdown()
    }

    @Test("Account-key rotation on master preserves every linked device's per-device signingPublicKey byte-for-byte")
    func accountKeyRotationPreservesPerDeviceKeys() async throws {
        _ = try await setupRotatableSession()

        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        let accountSigningKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: context.sessionUser.deviceKeys.signingPrivateKey
        )
        let masterDevice = try currentDevice(from: context)

        let firstChild = try makeUniqueLinkedSignedDevice(
            accountSigningKey: accountSigningKey,
            currentDeviceTemplate: masterDevice
        )
        let secondChild = try makeUniqueLinkedSignedDevice(
            accountSigningKey: accountSigningKey,
            currentDeviceTemplate: masterDevice
        )

        context.activeUserConfiguration.signedDevices.append(firstChild.signed)
        context.activeUserConfiguration.signedDevices.append(secondChild.signed)
        await store.setUserConfigurations(index: 0, config: context.activeUserConfiguration)
        try await persist(context: context)

        let perDeviceKeysBefore = try Self.collectPerDeviceKeys(
            from: context.activeUserConfiguration,
            accountKeyBytes: context.activeUserConfiguration.signingPublicKey
        )

        try await session.rotateKeysOnPotentialCompromise()

        guard let rotatedContext = await session.sessionContext else {
            Issue.record("Rotated context should be available")
            return
        }

        // New account public key must be different from the original account key.
        #expect(rotatedContext.activeUserConfiguration.signingPublicKey != context.activeUserConfiguration.signingPublicKey,
               "Account-level signingPublicKey must change after compromise rotation")

        let perDeviceKeysAfter = try Self.collectPerDeviceKeys(
            from: rotatedContext.activeUserConfiguration,
            accountKeyBytes: rotatedContext.activeUserConfiguration.signingPublicKey
        )

        #expect(perDeviceKeysAfter.count == perDeviceKeysBefore.count,
               "Device count must not change across account-key rotation")

        // Every linked-device entry must still verify under the NEW account key, and its
        // inner per-device signingPublicKey must equal the pre-rotation byte sequence —
        // except the master entry, whose per-device key is bound to the account key in
        // this conflated model and therefore rotates alongside it.
        for (deviceId, beforeKey) in perDeviceKeysBefore {
            guard let afterKey = perDeviceKeysAfter[deviceId] else {
                Issue.record("Device \(deviceId) disappeared after rotation")
                continue
            }
            if deviceId == context.sessionUser.deviceId {
                // Master's per-device entry tracks the new account key by design.
                #expect(afterKey == rotatedContext.activeUserConfiguration.signingPublicKey,
                       "Master per-device key should equal the new account public key")
            } else {
                #expect(afterKey == beforeKey,
                       "Linked device \(deviceId) per-device key must be preserved byte-for-byte across account rotation")
            }
        }

        await session.shutdown()
    }

    @Test("startSession tolerates per-device signingPrivateKey divergence (diagnostic-only)")
    func startSessionTolerantOfDivergedDeviceIdentity() async throws {
        _ = try await setupRotatableSession()

        guard var context = await session.sessionContext else {
            Issue.record("Session context should be initialized")
            return
        }

        // The historical write-master-key-onto-child overwrite is now blocked at the source
        // (private setter on `DeviceKeys.signingPrivateKey`, no private key on the
        // `LinkedDeviceReprovisioningBundle` wire format, and an explicit foreign-key rejection
        // inside `installLinkedDeviceReprovisioningBundle`). The remaining startSession check
        // is intentionally non-fatal so legitimate transient post-link states do not block
        // recovery; this test pins that contract.
        let foreignKey = Curve25519.Signing.PrivateKey()
        let originalDeviceKeys = context.sessionUser.deviceKeys
        context.sessionUser.deviceKeys = DeviceKeys(
            deviceId: originalDeviceKeys.deviceId,
            signingPrivateKey: foreignKey.rawRepresentation,
            longTermPrivateKey: originalDeviceKeys.longTermPrivateKey,
            oneTimePrivateKeys: originalDeviceKeys.oneTimePrivateKeys,
            mlKEMOneTimePrivateKeys: originalDeviceKeys.mlKEMOneTimePrivateKeys,
            finalMLKEMPrivateKey: originalDeviceKeys.finalMLKEMPrivateKey,
            rotateKeysDate: originalDeviceKeys.rotateKeysDate
        )
        try await persist(context: context)

        let appPassword = await session.appPassword
        _ = try await session.startSession(appPassword: appPassword)

        guard let postContext = await session.sessionContext else {
            Issue.record("Session context should still be loaded after diagnostic-only divergence")
            return
        }
        #expect(postContext.sessionUser.deviceKeys.signingPrivateKey == foreignKey.rawRepresentation,
               "startSession must not silently rewrite the persisted local signing key")

        await session.shutdown()
    }

    // MARK: - Private utilities

    private static func collectPerDeviceKeys(
        from config: UserConfiguration,
        accountKeyBytes: Data
    ) throws -> [UUID: Data] {
        let accountKey = try Curve25519.Signing.PublicKey(rawRepresentation: accountKeyBytes)
        var result: [UUID: Data] = [:]
        for signed in config.signedDevices {
            guard let verified = try signed.verified(using: accountKey) else {
                throw PQSSession.SessionErrors.invalidSignature
            }
            result[verified.deviceId] = verified.signingPublicKey
        }
        return result
    }
}
