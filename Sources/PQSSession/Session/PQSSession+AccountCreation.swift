//
//  PQSSession+AccountCreation.swift
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

/// Account bootstrap: cryptographic bundle/long-term key generation and
/// `createAccount`.
extension PQSSession {
    public struct OutOfBandResendResult: Sendable, Equatable {
        public let queuedIds: [String]
        /// Requested ids with no local replay source; the requester should stop retrying these.
        public let permanentlyUnavailableIds: [String]

        public init(queuedIds: [String], permanentlyUnavailableIds: [String]) {
            self.queuedIds = queuedIds
            self.permanentlyUnavailableIds = permanentlyUnavailableIds
        }
    }

    public struct CryptographicBundle: Sendable {
        /// Long-term curve / signing / ML-KEM material for this device.
        public let deviceKeys: DeviceKeys
        /// Per-device configuration to be added to the account-level
        /// ``UserConfiguration``.
        public let deviceConfiguration: UserDeviceConfiguration
        /// The (possibly newly minted) account-level ``UserConfiguration``
        /// containing this device.
        public let userConfiguration: UserConfiguration
    }

    /// A typed `(publicKey, privateKey)` pair tagged with a stable UUID.
    ///
    /// The SDK uses `KeyPair` for one-time prekey generation and for the
    /// long-term signing / agreement keys so every key has a unique
    /// identifier independent of its serialized representation.
    public struct KeyPair<Public, Private> {
        /// Stable identifier for the pair.
        public let id: UUID
        /// Public half of the pair.
        public let publicKey: Public
        /// Private half of the pair. Treat as secret.
        public let privateKey: Private

        public init(id: UUID, publicKey: Public, privateKey: Private) {
            self.id = id
            self.publicKey = publicKey
            self.privateKey = privateKey
        }
    }

    struct PrivateKeys: Sendable {
        let x25519: Curve25519.KeyAgreement.PrivateKey
        let signing: Curve25519.Signing.PrivateKey
        let mlKem: MLKEM1024.PrivateKey
    }

    func createLongTermKeys() throws -> PrivateKeys {
        let x25519 = crypto.generateCurve25519PrivateKey()
        let signing = crypto.generateCurve25519SigningPrivateKey()
        let mlKem = try crypto.generateMLKem1024PrivateKey()
        return PrivateKeys(
            x25519: x25519,
            signing: signing,
            mlKem: mlKem
        )
    }

    /// Creates a cryptographic bundle for a device, including keys and configurations.
    ///
    /// This asynchronous function generates a set of cryptographic keys for a device,
    /// either as a master device or a child device. It creates long-term and one-time
    /// keys, signs the device configuration, and prepares the data for publishing to
    /// the server. The generated keys can be presented as a QR code for easy scanning
    /// by other devices.
    ///
    /// - Parameter isMaster: A boolean indicating whether the device being created is
    ///                       a master device or a child device.
    ///
    /// - Throws:
    ///   - `PQSErrors`: If there is an error generating keys or creating configurations.
    ///
    /// - Returns: A `CryptographicBundle` containing the generated device keys, device
    ///            configuration, and user configuration.
    public func createDeviceCryptographicBundle(isMaster: Bool) async throws -> CryptographicBundle {
        let longTerm = try createLongTermKeys()

        // Generate one-time key pairs
        let x25519OneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let privateKeyRep = try X25519PrivateKey(id: id, privateKey.rawRepresentation)
            let publicKey = try X25519PublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }

        let mlKEMOneTimeKeyPairs: [KeyPair] = try (0 ..< PQSSessionConstants.oneTimeKeyBatchSize).map { _ in
            let id = UUID()
            let privateKey = try crypto.generateMLKem1024PrivateKey()
            let privateKeyRep = try MLKEMPrivateKey(id: id, privateKey.encode())
            let publicKey = try MLKEMPublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }

        let mlKEMId = UUID()
        let mlKEMPrivateKey = try MLKEMPrivateKey(id: mlKEMId, longTerm.mlKem.encode())
        let mlKEMPublicKey = try MLKEMPublicKey(id: mlKEMId, longTerm.mlKem.publicKey.rawRepresentation)

        // Create a unique device ID
        let deviceId = UUID()

        // Generate HMAC data for the device
        let hmacData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

        // Create device keys object
        let deviceKeys = DeviceKeys(
            deviceId: deviceId,
            signingPrivateKey: longTerm.signing.rawRepresentation,
            longTermPrivateKey: longTerm.x25519.rawRepresentation,
            oneTimePrivateKeys: x25519OneTimeKeyPairs.map(\.privateKey),
            mlKEMOneTimePrivateKeys: mlKEMOneTimeKeyPairs.map(\.privateKey),
            finalMLKEMPrivateKey: mlKEMPrivateKey,
            rotateKeysDate: Calendar.current.date(byAdding: .weekOfYear, value: 1, to: Date())
        )

        // Create a user device configuration
        let device = UserDeviceConfiguration(
            deviceId: deviceKeys.deviceId,
            signingPublicKey: longTerm.signing.publicKey.rawRepresentation,
            longTermPublicKey: longTerm.x25519.publicKey.rawRepresentation,
            finalMLKEMPublicKey: mlKEMPublicKey,
            deviceName: getDeviceName(),
            hmacData: hmacData,
            isMasterDevice: isMaster,
            lastSeenAt: Date()
        )

        // Sign the device configuration
        let signedDeviceConfiguration = try UserConfiguration.SignedDeviceConfiguration(
            device: device,
            signingKey: longTerm.signing
        )

        // Create signed public one-time keys for each one-time key pair
        let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try x25519OneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedOneTimePublicKey(
                key: keyPair.publicKey,
                deviceId: deviceId,
                signingKey: longTerm.signing
            )
        }

        let signedPublicMLKEMOneTimeKeys: [UserConfiguration.SignedMLKEMOneTimeKey] = try mlKEMOneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedMLKEMOneTimeKey(
                key: keyPair.publicKey,
                deviceId: deviceId,
                signingKey: longTerm.signing
            )
        }

        let signedDeviceKeyBundle = try UserConfiguration.SignedDeviceKeyBundle(
            bundle: .init(
                deviceId: deviceId,
                longTermPublicKey: longTerm.x25519.publicKey.rawRepresentation,
                finalMLKEMPublicKey: mlKEMPublicKey
            ),
            signingKey: longTerm.signing
        )

        // Create the user configuration with the signed device and keys
        let userConfiguration = UserConfiguration(
            signingPublicKey: longTerm.signing.publicKey.rawRepresentation,
            signedDevices: [signedDeviceConfiguration],
            signedOneTimePublicKeys: signedOneTimePublicKeys,
            signedMLKEMOneTimePublicKeys: signedPublicMLKEMOneTimeKeys,
            signedDeviceKeyBundles: [signedDeviceKeyBundle]
        )

        // Return the complete cryptographic bundle
        return CryptographicBundle(
            deviceKeys: deviceKeys,
            deviceConfiguration: device,
            userConfiguration: userConfiguration
        )
    }

    /// Generates a symmetric key for database encryption.
    ///
    /// This private function creates a symmetric key of 256 bits for encrypting
    /// database models. The key is returned as a `Data` object.
    ///
    /// - Returns: A `Data` object representing the generated database encryption key.
    func generateDatabaseEncryptionKey() -> Data {
        let databaseSymmetricKey = SymmetricKey(size: .bits256)
        return databaseSymmetricKey.withUnsafeBytes { Data($0) }
    }

    /// Creates a new session with the provided secret name and application password.
    ///
    /// This method generates cryptographic keys, retrieves necessary salts, and attempts to create a session
    /// for the user. It handles both the registration of a new device and the retrieval of existing user
    /// configurations. If the connection is not viable, an error is thrown.
    ///
    /// - Parameters:
    ///   - secretName: The name of the secret associated with the session.
    ///   - appPassword: The application password used for encryption and session management.
    /// - Returns: A `PQSSession` object representing the created session.
    /// - Throws: An error of type `PQSError` if the session creation fails due to various reasons.
    public func createAccount(
        secretName: String,
        appPassword: String,
        createInitialTransport: @Sendable @escaping () async throws -> Void
    ) async throws -> PQSSession {
        await setAppPassword(appPassword)
        // Match the canonical normalization used by the transport layer and
        // by `createContact` so the local user's identity stays consistent
        // with how it'll be referenced by every other code path.
        let secretName = SecretName(secretName).rawValue
        // Ensure identity store is initialized
        guard let cache else {
            throw PQSError.databaseNotInitialized
        }
        try await reviveAfterShutdownIfNeeded()
        await beginSessionLifecycleIfNeeded()

        let bundle = try await createDeviceCryptographicBundle(isMaster: true)
        let sessionUser = SessionUser(
            secretName: secretName,
            deviceId: bundle.deviceKeys.deviceId,
            deviceKeys: bundle.deviceKeys)

        var sessionContext = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: generateDatabaseEncryptionKey(),
            sessionContextId: .random(in: 1 ..< .max),
            activeUserConfiguration: bundle.userConfiguration,
            registrationState: .unregistered
        )
        await setSessionContext(sessionContext)

        guard let passwordData = appPassword.data(using: .utf8) else {
            throw PQSError.appPasswordError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        let appSymmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        let databaseEncryptionKey = try await getDatabaseSymmetricKey()

        try await createInitialTransport()

        // Check if the connection is viable
        guard isViable else {
            throw PQSError.connectionIsNonViable
        }

        // Attempt to find user configuration and handle registration
        do {
            // We are registering a new device to the main device if this succeeds
            if try await transportDelegate?.findConfiguration(for: secretName) != nil {
                throw PQSError.userExists
            }

            // SHOULD NEVER HAPPEN
            throw PQSError.unknownError
        } catch let sessionError as PQSError {
            switch sessionError {
            case .userExists:
                throw sessionError

            case .userNotFound:
                // UserConfiguration does not contain Private keys/info... so it should be safe to store publicly.
                try await transportDelegate?.publishUserConfiguration(
                    bundle.userConfiguration,
                    recipient: secretName,
                    recipient: bundle.deviceKeys.deviceId
                )

                sessionContext.registrationState = .registered
                await setSessionContext(sessionContext)

                let encodedData = try BinaryEncoder().encode(sessionContext)
                guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: appSymmetricKey) else {
                    throw PQSError.sessionEncryptionError
                }

                // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
                try await cache.createLocalSessionContext(encryptedConfig)

                // Create Communication Model for personal messages
                self.logger.log(level: .debug, message: "Creating Communication Model")

                let communicationModel = try await messagePipeline.createCommunicationModel(
                    recipients: [secretName],
                    communicationType: .personalMessage,
                    symmetricKey: databaseEncryptionKey
                )

                guard var props = await communicationModel.props(symmetricKey: databaseEncryptionKey) else {
                    throw PQSError.propsError
                }
                // Used to communicated between personal messages in this case
                props.sharedId = UUID()

                _ = try await communicationModel.updateProps(symmetricKey: databaseEncryptionKey, props: props)

                try await cache.createCommunication(communicationModel)
                await receiverDelegate?.updatedCommunication(communicationModel, members: [secretName])
                self.logger.log(level: .debug, message: "Created Communication Model")

            default:
                throw sessionError
            }
        } catch {
            logger.log(level: .error, message: "Error Creating Session, \(error)")
            throw error
        }
        return self
    }
}
