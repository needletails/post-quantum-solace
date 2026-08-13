//
//  PQSSession+DeviceLinking.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-12.
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
import NeedleTailLogger
import SessionEvents
import SessionModels

/// Device linking and user-configuration adoption: `linkDevice`,
/// verified-configuration acknowledgement, and device/key updates.
extension PQSSession {

    /// This call must be followed by start session.
    /// Links a device to the current session by generating cryptographic credentials.
    ///
    /// This asynchronous function links a new device to the current session by
    /// generating cryptographic credentials based on the provided device configuration
    /// and password. It creates a session identity, derives a symmetric key, and
    /// sets up the session context. It also creates a communication model for personal
    /// messages. This call must be followed by a call to `unlock`.
    ///
    /// - Parameters:
    ///   - bundle: A `CryptographicBundle` containing the device configuration and keys.
    ///   - password: A string representing the password used for cryptographic operations.
    ///
    /// - Throws:
    ///   - `PQSError.databaseNotInitialized`: If the cache is not initialized.
    ///   - `PQSError.appPasswordError`: If there is an error retrieving the password data.
    ///   - `PQSError.sessionEncryptionError`: If the session context cannot be encrypted successfully.
    ///   - `PQSError.registrationError`: If the device linking process fails.
    ///   - `PQSError.propsError`: If there is an error retrieving or updating properties in the communication model.
    ///
    /// - Returns: A `PQSSession` object representing the newly created session.
    public func linkDevice(
        bundle: CryptographicBundle,
        password: String
    ) async throws -> PQSSession {
        // Set the application password
        await setAppPassword(password)

        let linkConfig = try UserDeviceConfiguration(
            deviceId: bundle.deviceConfiguration.deviceId,
            signingPublicKey: Data(),
            longTermPublicKey: Data(),
            finalMLKEMPublicKey: .init(Data(count: 1568)),
            deviceName: bundle.deviceConfiguration.deviceName,
            hmacData: bundle.deviceConfiguration.hmacData,
            isMasterDevice: bundle.deviceConfiguration.isMasterDevice,
            lastSeenAt: Date()
        )

        // Encode the device configuration to prepare for QR code generation
        let data = try BinaryEncoder().encode(linkConfig)

        // Generate cryptographic credentials for device linking
        if let credentials = await linkDelegate?.generateDeviceCryptographic(data, password: password) {
            guard let cache else {
                throw PQSError.databaseNotInitialized
            }

            // Set the application password from the generated credentials
            await setAppPassword(credentials.password)

            // Create a Session Identity
            let sessionUser = SessionUser(
                secretName: credentials.secretName,
                deviceId: bundle.deviceKeys.deviceId,
                deviceKeys: bundle.deviceKeys)

            // Generate a symmetric key for encrypting local database models
            let databaseEncryptionKey = generateDatabaseEncryptionKey()

            let userConfiguration: UserConfiguration
            if var linkedConfiguration = credentials.userConfiguration {
                let verifiedDevices = try linkedConfiguration.getVerifiedDevices()
                guard let localDevice = verifiedDevices.first(where: { $0.deviceId == bundle.deviceKeys.deviceId }) else {
                    throw PQSError.invalidDeviceIdentity
                }
                let localSigningKey = try Curve25519.Signing.PrivateKey(
                    rawRepresentation: bundle.deviceKeys.signingPrivateKey)
                guard localDevice.signingPublicKey == localSigningKey.publicKey.rawRepresentation else {
                    throw PQSError.deviceIdentityCorrupted
                }

                let localX25519Keys = bundle.userConfiguration.signedOneTimePublicKeys.filter {
                    $0.deviceId == bundle.deviceKeys.deviceId
                }
                var x25519KeysById = Dictionary(uniqueKeysWithValues: linkedConfiguration.signedOneTimePublicKeys.map {
                    ($0.id, $0)
                })
                for key in localX25519Keys {
                    x25519KeysById[key.id] = key
                }
                linkedConfiguration.signedOneTimePublicKeys = Array(x25519KeysById.values)

                let localMLKEMKeys = bundle.userConfiguration.signedMLKEMOneTimePublicKeys.filter {
                    $0.deviceId == bundle.deviceKeys.deviceId
                }
                var mlkemKeysById = Dictionary(uniqueKeysWithValues: linkedConfiguration.signedMLKEMOneTimePublicKeys.map {
                    ($0.id, $0)
                })
                for key in localMLKEMKeys {
                    mlkemKeysById[key.id] = key
                }
                linkedConfiguration.signedMLKEMOneTimePublicKeys = Array(mlkemKeysById.values)

                if let localBundle = bundle.userConfiguration.signedDeviceKeyBundles.last(where: {
                    $0.id == bundle.deviceKeys.deviceId
                }), !linkedConfiguration.signedDeviceKeyBundles.contains(where: {
                    $0.id == bundle.deviceKeys.deviceId
                }) {
                    linkedConfiguration.signedDeviceKeyBundles.append(localBundle)
                }
                try validateLinkedDeviceConfiguration(
                    linkedConfiguration,
                    localDeviceId: bundle.deviceKeys.deviceId
                )
                userConfiguration = linkedConfiguration
            } else {
                // Legacy link delegates only return bare devices. Keep this as a compatibility
                // fallback, but modern device linking should supply `userConfiguration`.
                userConfiguration = try await createNewUser(
                    configuration: bundle.userConfiguration,
                    signingPrivateKeyData: bundle.deviceKeys.signingPrivateKey,
                    devices: credentials.devices,
                    keys: bundle.userConfiguration.getVerifiedX25519Keys(deviceId: bundle.deviceKeys.deviceId),
                    mlKEMKeys: bundle.userConfiguration.getVerifiedMLKEMKeys(deviceId: bundle.deviceKeys.deviceId))
            }

            // Create a new session context with the session user and user configuration
            var sessionContext = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: databaseEncryptionKey,
                sessionContextId: .random(in: 1 ..< .max),
                activeUserConfiguration: userConfiguration,
                registrationState: .unregistered)

            // Set the session context
            await setSessionContext(sessionContext)

            // Convert the password to data for deriving the symmetric key
            guard let passwordData = credentials.password.data(using: .utf8) else {
                throw PQSError.appPasswordError
            }

            // Retrieve salt and derive the symmetric key
            let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)
            let symmetricKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData)

            // Update the registration state to registered
            sessionContext.registrationState = .registered
            await setSessionContext(sessionContext)

            // Encode the updated session context for encryption
            let encodedData = try BinaryEncoder().encode(sessionContext)

            // Encrypt the session context using the derived symmetric key
            guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
                throw PQSError.sessionEncryptionError
            }

            // Create a local session context with the encrypted data
            try await cache.createLocalSessionContext(encryptedConfig)

            // Create a communication model for personal messages
            logger.log(level: .debug, message: "Creating Communication Model")
            let databaseSymmetricKey = try await getDatabaseSymmetricKey()
            let communicationModel = try await messagePipeline.createCommunicationModel(
                recipients: [credentials.secretName],
                communicationType: .personalMessage,
                symmetricKey: databaseSymmetricKey)

            // Update properties of the communication model
            guard var props = await communicationModel.props(symmetricKey: databaseSymmetricKey) else {
                throw PQSError.propsError
            }

            props.sharedId = UUID()

            // Update the communication model with the new properties
            _ = try await communicationModel.updateProps(symmetricKey: databaseSymmetricKey, props: props)

            // Create the communication in the cache
            try await cache.createCommunication(communicationModel)

            // Notify the receiver delegate about the updated communication model
            await receiverDelegate?.updatedCommunication(communicationModel, members: [credentials.secretName])
            logger.log(level: .debug, message: "Created Communication Model")

            // Start the session and return the PQSSession
            return try await unlock(appPassword: credentials.password)
        } else {
            throw PQSError.registrationError
        }
    }

    /// The local user's stable `SecurityIdentity`, suitable for computing safety
    /// numbers against a remote contact (`SecurityIdentity.safetyNumber(local:remote:)`).
    ///
    /// Returns `nil` if the session is not yet initialized.
    public func localSecurityIdentity() async -> SecurityIdentity? {
        guard let context = await sessionContext else { return nil }
        return SecurityIdentity(
            secretName: context.sessionUser.secretName,
            configuration: context.activeUserConfiguration
        )
    }

    private func validateLinkedDeviceConfiguration(
        _ configuration: UserConfiguration,
        localDeviceId: UUID
    ) throws {
        let verified = try configuration.getVerifiedDevices()
        guard verified.count == configuration.signedDevices.count,
              verified.contains(where: { $0.deviceId == localDeviceId })
        else {
            throw PQSError.invalidSignature
        }

        for signedBundle in configuration.signedDeviceKeyBundles {
            guard let device = verified.first(where: { $0.deviceId == signedBundle.id }) else {
                throw PQSError.invalidDeviceIdentity
            }
            let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
            guard let bundle = try signedBundle.verified(using: deviceSigningKey),
                  bundle.deviceId == device.deviceId
            else {
                throw PQSError.invalidSignature
            }
        }
    }

    func userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
        _ incomingConfiguration: UserConfiguration,
        currentContext: SessionContext
    ) -> UserConfiguration {
        let deviceId = currentContext.sessionUser.deviceId
        guard let verifiedDevice = try? incomingConfiguration.getVerifiedDevices().first(where: {
            $0.deviceId == deviceId
        }),
              let deviceSigningKey = try? Curve25519.Signing.PublicKey(
                rawRepresentation: verifiedDevice.signingPublicKey
              )
        else {
            return incomingConfiguration
        }

        let localX25519Keys = currentContext.activeUserConfiguration.signedOneTimePublicKeys
            .filter { $0.deviceId == deviceId }
            .filter { (try? $0.verified(using: deviceSigningKey)) != nil }
        let localMLKEMKeys = currentContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys
            .filter { $0.deviceId == deviceId }
            .filter { (try? $0.verified(using: deviceSigningKey)) != nil }

        guard !localX25519Keys.isEmpty || !localMLKEMKeys.isEmpty else {
            return incomingConfiguration
        }

        var mergedConfiguration = incomingConfiguration
        if !localX25519Keys.isEmpty {
            mergedConfiguration.signedOneTimePublicKeys.removeAll { $0.deviceId == deviceId }
            mergedConfiguration.signedOneTimePublicKeys.append(contentsOf: localX25519Keys)
        }
        if !localMLKEMKeys.isEmpty {
            mergedConfiguration.signedMLKEMOneTimePublicKeys.removeAll { $0.deviceId == deviceId }
            mergedConfiguration.signedMLKEMOneTimePublicKeys.append(contentsOf: localMLKEMKeys)
        }

        return mergedConfiguration
    }

    /// Adopts a `UserConfiguration` that has already been verified against its own
    /// `signingPublicKey` (e.g. one returned from the server's `findConfiguration`
    /// endpoint, where every signed entry was produced by the master's account-level
    /// signing key).
    ///
    /// Use this from refresh / sync paths where the configuration originates from a
    /// trusted, already-verified source. Unlike `updateUserConfiguration(_:)`, this
    /// does NOT re-sign anything with the local device's per-device signing key, so it
    /// is safe on linked (child) devices whose per-device signing key intentionally
    /// differs from the account-level `signingPublicKey`.
    ///
    /// ## Trust model (TOFU)
    /// The account-level `signingPublicKey` is pinned on first set. A subsequent
    /// adoption whose `signingPublicKey` differs from the locally pinned value is
    /// rejected with `PQSError.signingKeyOutOfSync`. Legitimate rotations must
    /// arrive over a verified rotation channel (e.g. a master-signed reprovisioning
    /// bundle via `installLinkedDeviceReprovisioningBundle`, or this device performing
    /// its own `rotateKeysOnPotentialCompromise`), not a server refresh.
    ///
    /// - Parameter configuration: The fully-signed `UserConfiguration` to adopt.
    /// - Throws: `PQSError.invalidSignature` if `configuration` is not
    ///           internally consistent; `PQSError.signingKeyOutOfSync` if the
    ///           account signing key differs from the pinned value; plus the usual
    ///           session/cache errors.
    public func adoptVerifiedUserConfiguration(_ configuration: UserConfiguration) async throws {
        // 1. Internal consistency: every signed device must verify under the
        //    configuration's own signingPublicKey. `getVerifiedDevices` silently filters
        //    bad entries via compactMap, so cross-check the count.
        let verified = try configuration.getVerifiedDevices()
        guard verified.count == configuration.signedDevices.count else {
            throw PQSError.invalidSignature
        }
        for signedBundle in configuration.signedDeviceKeyBundles {
            guard let device = verified.first(where: { $0.deviceId == signedBundle.id }) else {
                throw PQSError.invalidDeviceIdentity
            }
            let deviceSigningKey = try Curve25519.Signing.PublicKey(rawRepresentation: device.signingPublicKey)
            guard let bundle = try signedBundle.verified(using: deviceSigningKey),
                  bundle.deviceId == device.deviceId
            else {
                throw PQSError.invalidSignature
            }
        }

        guard let cache else { return }
        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }

        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        // 2. TOFU pin on the account-level signing key. A change here is a security
        //    event (potential server-side identity swap) and must NOT be silently
        //    accepted. Legitimate rotations install via the reprovisioning bundle
        //    or `rotateKeysOnPotentialCompromise`, both of which update the local
        //    pin first, so a subsequent refresh sees a matching key.
        let pinnedKey = sessionContext.activeUserConfiguration.signingPublicKey
        if !pinnedKey.isEmpty, pinnedKey != configuration.signingPublicKey {
            logger.log(
                level: .error,
                message: "[adoptVerifiedUserConfiguration] account signing key changed without an authenticated rotation; refusing to adopt. pinnedPrefix=\(pinnedKey.prefix(8).map { String(format: "%02x", $0) }.joined()) incomingPrefix=\(configuration.signingPublicKey.prefix(8).map { String(format: "%02x", $0) }.joined())"
            )
            setAccountIdentityRequiresAcknowledgement(true)
            throw PQSError.signingKeyOutOfSync
        }

        // Healthy adoption restores the TOFU pin match; clear any prior mismatch gate.
        setAccountIdentityRequiresAcknowledgement(false)

        sessionContext.activeUserConfiguration = userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
            configuration,
            currentContext: sessionContext
        )
        await setSessionContext(sessionContext)

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    /// Explicitly clears the locally pinned account-level signing key and adopts
    /// `proposedConfiguration`'s signing key in its place. This is the **only**
    /// path allowed to overwrite the TOFU pin via a server-supplied configuration
    /// and is intended exclusively for an authenticated, user-initiated trust
    /// re-establishment after a legitimate rotation that bypassed the normal
    /// channels (lost master, restore-from-backup, server reset during private
    /// beta, etc.).
    ///
    /// > Important: Callers MUST gate this behind a strong, explicit user
    /// > confirmation (e.g. an in-app passcode, OS biometrics, or a typed
    /// > destructive phrase). Anyone who can call this can replace the trust
    /// > anchor for the local account; treat it like "remove all locks and
    /// > re-key the front door".
    ///
    /// On success, the new configuration's `signingPublicKey` becomes the new
    /// pin. Subsequent `adoptVerifiedUserConfiguration(_:)` calls (e.g. the
    /// background refresh path) will accept matching configurations and reject
    /// any further drift, restoring the normal TOFU invariant.
    ///
    /// The transition is logged at `.error` so it is grep-able in support
    /// triage even if the device's logs are filtered to errors only.
    ///
    /// - Parameter proposedConfiguration: A `UserConfiguration` whose internal
    ///   signatures verify against its own `signingPublicKey`. Typically
    ///   obtained by re-fetching `findConfiguration(for:)` from the transport.
    /// - Throws:
    ///   - `PQSError.invalidSignature` if the proposed configuration is
    ///     not internally consistent (signed devices don't all verify under
    ///     the configuration's own signing key).
    ///   - `PQSError.sessionDecryptionError` / `sessionEncryptionError`
    ///     for the usual cache/crypto failure modes.
    public func acknowledgeAccountIdentityChange(_ proposedConfiguration: UserConfiguration) async throws {
        // Internal consistency: never overwrite the pin with a malformed config.
        let verified = try proposedConfiguration.getVerifiedDevices()
        guard verified.count == proposedConfiguration.signedDevices.count else {
            throw PQSError.invalidSignature
        }

        guard let cache else { return }
        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }

        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        let oldKey = sessionContext.activeUserConfiguration.signingPublicKey
        let newKey = proposedConfiguration.signingPublicKey

        // Idempotent no-op: nothing to acknowledge.
        guard oldKey != newKey else {
            sessionContext.activeUserConfiguration = userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
                proposedConfiguration,
                currentContext: sessionContext
            )
            await setSessionContext(sessionContext)
            let encodedData = try BinaryEncoder().encode(sessionContext)
            guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
                throw PQSError.sessionEncryptionError
            }
            try await cache.updateLocalSessionContext(encryptedConfig)
            setAccountIdentityRequiresAcknowledgement(false)
            return
        }

        logger.log(
            level: .error,
            message: "[acknowledgeAccountIdentityChange] user-acknowledged account signing key change. oldPrefix=\(oldKey.prefix(8).map { String(format: "%02x", $0) }.joined()) newPrefix=\(newKey.prefix(8).map { String(format: "%02x", $0) }.joined()) deviceCount=\(verified.count)"
        )

        sessionContext.activeUserConfiguration = userConfigurationPreservingLocalCurrentDeviceOneTimeKeys(
            proposedConfiguration,
            currentContext: sessionContext
        )
        await setSessionContext(sessionContext)

        let encodedData = try BinaryEncoder().encode(sessionContext)
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }
        try await cache.updateLocalSessionContext(encryptedConfig)

        // Pin is now trusted. Close any zombie same-account recovery episodes that
        // opened before the ack so the next decrypt failure may emit peerRefresh.
        setAccountIdentityRequiresAcknowledgement(false)
        let localSecretName = sessionContext.sessionUser.secretName
        let staleKeys = openReestablishmentEpisodes.keys.filter { $0.hasPrefix("\(localSecretName)|") }
        for key in staleKeys {
            openReestablishmentEpisodes.removeValue(forKey: key)
            expectedPeerRefreshIntentByPeer.removeValue(forKey: key)
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            if parts.count == 2, let deviceId = UUID(uuidString: parts[1]) {
                await flushPendingResends(
                    sender: parts[0],
                    deviceId: deviceId,
                    reason: "identityAcknowledged")
            }
        }
        if !staleKeys.isEmpty {
            let delegate = sessionDelegate
            let keys = Array(staleKeys)
            // Protocol signal: the transport releases held offline ciphertext on it.
            _ = await scheduleTransportProtocolWork {
                for key in keys {
                    let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
                    guard parts.count == 2, let deviceId = UUID(uuidString: parts[1]) else { continue }
                    await delegate?.reestablishmentEpisodeDidEnd(
                        senderSecretName: parts[0],
                        senderDeviceId: deviceId)
                }
            }
        }
    }

    /// Updates the user's configuration with new device configurations.
    ///
    /// This asynchronous function updates the user's configuration by incorporating
    /// new device configurations. It retrieves the current session context from the
    /// cache, decrypts it, creates a new user configuration with the updated devices,
    /// and then re-encrypts the session context before saving it back to the cache.
    ///
    /// > Important: This is a **master-only** operation. It re-signs the resulting
    /// > `UserConfiguration` with the local device's signing key. On a linked (child)
    /// > device the per-device signing key intentionally differs from the account-level
    /// > `signingPublicKey`, so the resulting configuration would fail signature
    /// > verification. Calling this on a child throws `PQSError.signingKeyOutOfSync`.
    /// > Children should use `adoptVerifiedUserConfiguration(_:)` instead, which adopts
    /// > a server-signed configuration verbatim.
    ///
    /// - Parameter devices: An array of `UserDeviceConfiguration` objects representing
    ///                     the new devices to be associated with the user's configuration.
    ///
    /// - Throws:
    ///   - `PQSError.signingKeyOutOfSync`: If invoked on a linked (child) device.
    ///   - `PQSError.sessionDecryptionError`: If the session context cannot be
    ///     decrypted successfully.
    ///   - `PQSError.sessionEncryptionError`: If the updated session
    ///     context cannot be encrypted successfully.
    public func updateUserConfiguration(_ devices: [UserDeviceConfiguration]) async throws {
        // Retrieve the current session context from the cache
        guard let data = try await cache?.fetchLocalSessionContext() else { return }

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        // Master-only invariant: the local device must own the account signing key.
        // On a linked child this comparison fails because the per-device signing key
        // intentionally differs from the account-level `signingPublicKey`.
        let localSigningPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey
        )
        let localSigningPublicKey = localSigningPrivateKey.publicKey.rawRepresentation
        guard localSigningPublicKey == sessionContext.activeUserConfiguration.signingPublicKey else {
            logger.log(
                level: .error,
                message: "[updateUserConfiguration] refusing to re-sign configuration on a non-master device. This path requires the account signing key; child devices must call adoptVerifiedUserConfiguration."
            )
            throw PQSError.signingKeyOutOfSync
        }

        // Create a new user configuration with the updated devices
        let userConfiguration = try await createNewUser(
            configuration: sessionContext.activeUserConfiguration,
            signingPrivateKeyData: sessionContext.sessionUser.deviceKeys.signingPrivateKey,
            devices: devices,
            keys: sessionContext.activeUserConfiguration.getVerifiedX25519Keys(deviceId: sessionContext.sessionUser.deviceId),
            mlKEMKeys: sessionContext.activeUserConfiguration.getVerifiedMLKEMKeys(deviceId: sessionContext.sessionUser.deviceId)
        )

        // Update the last user configuration in the session context
        sessionContext.activeUserConfiguration = userConfiguration

        // Save the updated session context back to the cache
        await setSessionContext(sessionContext)

        // Encode the updated session context to prepare for encryption
        let encodedData = try BinaryEncoder().encode(sessionContext)

        // Encrypt the updated session context using the app's symmetric key
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }

        // Update the local session context in the cache with the encrypted data
        try await cache?.updateLocalSessionContext(encryptedConfig)
    }

    /// Updates the user's public one-time keys in the session context.
    ///
    /// This asynchronous function updates the user's public one-time keys in the
    /// existing session context. It retrieves the current session context from the
    /// cache, decrypts it, updates the public one-time keys, and then re-encrypts
    /// the session context before saving it back to the cache.
    ///
    /// - Parameter keys: An array of `UserConfiguration.SignedoneTimePublicKey` objects
    ///                   representing the new public one-time keys to be associated
    ///                   with the user's configuration.
    ///
    /// - Throws:
    ///   - `PQSError.sessionDecryptionError`: If the session context cannot be
    ///     decrypted successfully.
    ///   - `PQSError.sessionEncryptionError`: If the updated session
    ///     context cannot be encrypted successfully.
    public func updateUserOneTimePublicKeys(_ keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {
        // Retrieve the current session context from the cache
        guard let data = try await cache?.fetchLocalSessionContext() else { return }

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
        var sessionContext = try BinaryDecoder().decode(SessionContext.self, from: configurationData)

        // Create a new UserConfiguration with the updated public one-time keys
        let userConfiguration = UserConfiguration(
            signingPublicKey: sessionContext.activeUserConfiguration.signingPublicKey,
            signedDevices: sessionContext.activeUserConfiguration.signedDevices,
            signedOneTimePublicKeys: keys,
            signedMLKEMOneTimePublicKeys: sessionContext.activeUserConfiguration.signedMLKEMOneTimePublicKeys,
            signedDeviceKeyBundles: sessionContext.activeUserConfiguration.signedDeviceKeyBundles
        )

        // Update the last user configuration in the session context
        sessionContext.activeUserConfiguration = userConfiguration

        // Save the updated session context back to the cache
        await setSessionContext(sessionContext)

        // Encode the updated session context to prepare for encryption
        let encodedData = try BinaryEncoder().encode(sessionContext)

        // Encrypt the updated session context using the app's symmetric key
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSError.sessionEncryptionError
        }

        // Update the local session context in the cache with the encrypted data
        try await cache?.updateLocalSessionContext(encryptedConfig)
    }

}
