//
//  PQSSession.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/12/24.
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

import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import Logging
import NeedleTailCrypto
import NeedleTailLogger
import SessionEvents
import SessionModels
import SwiftKyber

/// A secure, post-quantum cryptographic session manager for end-to-end encrypted messaging.
///
/// `PQSSession` is the central actor responsible for managing cryptographic sessions, key management,
/// and secure communication channels. It implements both classical (Curve25519) and post-quantum
/// (Kyber1024) cryptography to ensure long-term security against quantum attacks.
///
/// ## Overview
///
/// The session manager provides:
/// - **Post-quantum secure key exchange** using Kyber1024
/// - **Forward secrecy** through Double Ratchet protocol
/// - **Device management** with master/child device support
/// - **Automatic key rotation** and compromise recovery
/// - **End-to-end encryption** for all communications
///
/// ## Architecture
///
/// `PQSSession` follows a singleton pattern and uses Swift's actor model for thread-safe
/// concurrent access. It delegates specific responsibilities to protocol-conforming objects:
///
/// - `SessionTransport` - Network communication and key distribution
/// - `PQSSessionStore` - Persistent storage and caching
/// - `EventReceiver` - Event handling and UI updates
/// - `PQSSessionDelegate` - Application-specific session logic
///
/// ## Usage Example
///
/// ```swift
/// // Initialize the session
/// let session = PQSSession.shared
///
/// // Set up delegates
/// await session.setTransportDelegate(conformer: myTransport)
/// await session.setDatabaseDelegate(conformer: myStore)
/// session.setReceiverDelegate(conformer: myReceiver)
///
/// // Create a new session
/// try await session.createSession(
///     secretName: "alice",
///     appPassword: "securePassword",
///     createInitialTransport: setupTransport
/// )
///
/// // Start the session
/// try await session.startSession(appPassword: "securePassword")
///
/// // Send a message
/// try await session.writeTextMessage(
///     recipient: .nickname("bob"),
///     text: "Hello, world!",
///     metadata: ["timestamp": Date()],
///     destructionTime: 3600
/// )
/// ```
///
/// ## Security Features
///
/// - **Post-quantum cryptography**: Kyber1024 for key exchange
/// - **Forward secrecy**: Double Ratchet protocol with automatic key rotation
/// - **Compromise recovery**: Key rotation on potential compromise
/// - **Device verification**: Signed device configurations
/// - **One-time keys**: Pre-generated keys for immediate communication
/// - **Perfect forward secrecy**: Keys are rotated after each message
///
/// ## Thread Safety
///
/// This actor is designed for concurrent access and all public methods are thread-safe.
/// The singleton pattern ensures consistent state across your application.
///
/// ## Error Handling
///
/// All methods throw specific `SessionErrors` that provide clear information about
/// what went wrong and how to recover. Common errors include:
///
/// - `SessionErrors.sessionNotInitialized` - Session not properly set up
/// - `SessionErrors.databaseNotInitialized` - Storage not configured
/// - `SessionErrors.transportNotInitialized` - Network layer not ready
/// - `SessionErrors.invalidSignature` - Cryptographic verification failed
///
/// ## Performance Considerations
///
/// - Key generation is performed asynchronously
/// - One-time keys are pre-generated in batches of 100
/// - Automatic key refresh when supply is low
/// - Efficient caching of session identities
///
/// - Important: This actor is designed as a singleton. Always use `PQSSession.shared`
///   rather than creating new instances.
public actor PQSSession: NetworkDelegate, SessionCacheSynchronizer {
    /// Unique identifier for the session instance.
    /// This ID is generated once and remains constant for the lifetime of the session.
    nonisolated let id = UUID()

    /// Indicates whether the session is viable for cryptographic operations.
    ///
    /// This property is set to `true` when the session is properly initialized
    /// with all required delegates and cryptographic keys. It becomes `false`
    /// when the session is shut down or encounters critical errors.
    ///
    /// - Important: Always check this property before performing cryptographic operations.
    public nonisolated(unsafe) var isViable: Bool = false

    /// The shared singleton instance of `PQSSession`.
    ///
    /// Use this instance throughout your application to ensure consistent
    /// session state and avoid conflicts between multiple session managers.
    ///
    /// - Important: Never create new instances of `PQSSession`. Always use this shared instance.
    public static let shared = PQSSession()

    /// Public initializer to enforce singleton usage.
    ///
    /// This initializer is provided to support the singleton pattern.
    /// In practice, you should always use `PQSSession.shared` instead.
    public init() {}

    private(set) var _sessionContext: SessionContext?
    private var _appPassword = ""
    private(set) var taskProcessor = TaskProcessor()
    private(set) var transportDelegate: (any SessionTransport)?
    private(set) var receiverDelegate: (any EventReceiver)?
    private(set) var sessionDelegate: (any PQSSessionDelegate)?
    private(set) var eventDelegate: (any SessionEvents)?
    private var refreshOTKeysTask: Task<Void, Never>?
    private var refreshKyberOTKeysTask: Task<Void, Never>?
    public nonisolated(unsafe) weak var linkDelegate: DeviceLinkingDelegate?
    public var cache: SessionCache?
    let crypto = NeedleTailCrypto()
    var logger = NeedleTailLogger(.init(label: "[PQSSession]"))
    var sessionIdentities = Set<String>()
    var rotatingKeys = false
    var addingContactData: Data?

    // Asynchronously retrieves the current session context
    public var sessionContext: SessionContext? {
        get async {
            _sessionContext
        }
    }

    // Sets the session context
    public func setSessionContext(_ context: SessionContext) async {
        _sessionContext = context
    }

    // Asynchronously retrieves the application password
    public var appPassword: String {
        get async {
            _appPassword
        }
    }

    // Sets the application password
    func setAppPassword(_ password: String) async {
        _appPassword = password
    }

    // Sets the logger log level
    public func setLogLevel(_ level: Logging.Logger.Level) async {
        logger.setLogLevel(level)
    }

    public func setAddingContact(_ data: Data?) async {
        addingContactData = data
    }

    // Synchronizes the local configuration with the provided data
    func synchronizeLocalConfiguration(_ data: Data) async throws {
        let symmetricKey = try await getAppSymmetricKey()
        guard let decryptedData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else { return }
        let context = try BSONDecoder().decodeData(SessionContext.self, from: decryptedData)
        await setSessionContext(context)
    }

    /// Sets the transport delegate conforming to `SessionTransport`.
    /// - Parameter conformer: The conforming object to set as the transport delegate.
    public func setTransportDelegate(conformer: (any SessionTransport)?) async {
        transportDelegate = conformer
        await taskProcessor.setDelegate(conformer)
    }

    /// Sets the database delegate conforming to `IdentityStore`.
    /// - Parameter conformer: The conforming object to set as the identity store.
    public func setDatabaseDelegate(conformer: (any PQSSessionStore)?) async {
        if let conformer {
            cache = SessionCache(store: conformer)
            await cache?.setSynchronizer(self)
        }
    }

    // Sets the receiver delegate
    public func setReceiverDelegate(conformer: (any EventReceiver)?) {
        receiverDelegate = conformer
    }

    // Sets the crypto session delegate
    public func setPQSSessionDelegate(conformer: (any PQSSessionDelegate)?) async {
        if let conformer {
            sessionDelegate = conformer
        }
    }

    // Sets the session event delegate
    public func setSessionEventDelegate(conformer: (any SessionEvents)?) async {
        if let conformer {
            eventDelegate = conformer
        }
    }

    // Enum representing various session-related errors
    public enum SessionErrors: String, Error {
        case saltError = "Salt error occurred."
        case databaseNotInitialized = "Database is not initialized."
        case sessionNotInitialized = "Session is not initialized."
        case transportNotInitialized = "Transport is not initialized."
        case sessionEncryptionError = "Session encryption error."
        case sessionDecryptionError = "Session decryption error."
        case connectionIsNonViable = "Connection is non-viable."
        case invalidPassword = "Invalid password."
        case invalidSecretName = "Invalid secret name."
        case invalidDeviceIdentity = "Invalid device identity."
        case missingSessionIdentity = "Missing session identity."
        case invalidSignature = "Invalid signature."
        case missingSignature = "Missing signature."
        case configurationError = "Configuration error."
        case cannotFindCommunication = "Cannot find communication."
        case cannotFindContact = "Cannot find contact."
        case propsError = "Properties error."
        case appPasswordError = "Application password error."
        case registrationError = "Registration error."
        case userExists = "User already exists."
        case cannotFindUserConfiguration = "Cannot find user configuration."
        case cannotFindOneTimeKey = "Cannot find a one-time key for the user."
        case oneTimeKeyUploadFailed = "Failed to upload one-time key for the user."
        case oneTimeKeyDeletionFailed = "Failed to delete one-time key for the user."
        case unknownError = "An unknown error occurred."
        case missingAuthInfo = "Missing authentication information in the payload."
        case userNotFound = "Could not find the user requested."
        case accessDenied = "Denied access to the requested resource."
        case userIsBlocked = "The user is blocked; cannot request friendship changes."
        case missingMessage = "The message cannot be processed because it is missing."
        case missingMetadata = "The metadata is missing."
        case invalidDocument = "The document is invalid."
        case receiverDelegateNotSet = "The receiver delegate is not set."
        case invalidKeyId = "The Key ID is invalid."
        case drainedKeys = "The Local Keys are drained."
        case longTermKeyRotationFailed = "Failed to rotate the long-term key."
    }

    /// A struct representing a bundle of cryptographic data for a device.
    public struct CryptographicBundle: Sendable {
        public let deviceKeys: DeviceKeys // Keys associated with the device
        public let deviceConfiguration: UserDeviceConfiguration // Configuration for the device
        public let userConfiguration: UserConfiguration // User configuration associated with the device
    }

    /// A struct to represent a key pair with a UUID for both public and private keys.
    public struct KeyPair<Public, Private> {
        public let id: UUID // Unique identifier for the key pair
        public let publicKey: Public // Public key
        public let privateKey: Private // Private key

        public init(id: UUID, publicKey: Public, privateKey: Private) {
            self.id = id
            self.publicKey = publicKey
            self.privateKey = privateKey
        }
    }

    struct PrivateKeys: Sendable {
        let curve: Curve25519PrivateKey
        let signing: Curve25519SigningPrivateKey
        let kyber: Kyber1024.KeyAgreement.PrivateKey
    }

    func createLongTermKeys() throws -> PrivateKeys {
        let curve = crypto.generateCurve25519PrivateKey()
        let signing = crypto.generateCurve25519SigningPrivateKey()
        let kyber = try crypto.generateKyber1024PrivateSigningKey()
        return PrivateKeys(
            curve: curve,
            signing: signing,
            kyber: kyber
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
    ///   - `CryptoErrors`: If there is an error generating keys or creating configurations.
    ///
    /// - Returns: A `CryptographicBundle` containing the generated device keys, device
    ///            configuration, and user configuration.
    public func createDeviceCryptographicBundle(isMaster: Bool) async throws -> CryptographicBundle {
        let longTerm = try createLongTermKeys()

        // Generate 100 private one-time key pairs
        let curveOneTimeKeyPairs: [KeyPair] = try (0 ..< 100).map { _ in
            let id = UUID()
            let privateKey = crypto.generateCurve25519PrivateKey()
            let privateKeyRep = try CurvePrivateKey(id: id, privateKey.rawRepresentation)
            let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }

        let kyberOneTimeKeyPairs: [KeyPair] = try (0 ..< 100).map { _ in
            let id = UUID()
            let privateKey = try crypto.generateKyber1024PrivateSigningKey()
            let privateKeyRep = try PQKemPrivateKey(id: id, privateKey.encode())
            let publicKey = try PQKemPublicKey(id: id, privateKey.publicKey.rawRepresentation)
            return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
        }

        let kyberId = UUID()
        let kyberPrivateKey = try PQKemPrivateKey(id: kyberId, longTerm.kyber.encode())
        let kyberPublicKey = try PQKemPublicKey(id: kyberId, longTerm.kyber.publicKey.rawRepresentation)

        // Create a unique device ID
        let deviceId = UUID()

        // Generate HMAC data for the device
        let hmacData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

        // Create device keys object
        let deviceKeys = DeviceKeys(
            deviceId: deviceId,
            signingPrivateKey: longTerm.signing.rawRepresentation,
            longTermPrivateKey: longTerm.curve.rawRepresentation,
            oneTimePrivateKeys: curveOneTimeKeyPairs.map(\.privateKey),
            pqKemOneTimePrivateKeys: kyberOneTimeKeyPairs.map(\.privateKey),
            finalPQKemPrivateKey: kyberPrivateKey,
            rotateKeysDate: Calendar.current.date(byAdding: .weekOfYear, value: 1, to: Date())
        )

        // Create a user device configuration
        let device = UserDeviceConfiguration(
            deviceId: deviceKeys.deviceId,
            signingPublicKey: longTerm.signing.publicKey.rawRepresentation,
            longTermPublicKey: longTerm.curve.publicKey.rawRepresentation,
            finalPQKemPublicKey: kyberPublicKey,
            deviceName: getDeviceName(),
            hmacData: hmacData,
            isMasterDevice: isMaster
        )

        // Sign the device configuration
        let signedDeviceConfiguration = try UserConfiguration.SignedDeviceConfiguration(
            device: device,
            signingKey: longTerm.signing
        )

        // Create signed public one-time keys for each one-time key pair
        let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try curveOneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedOneTimePublicKey(
                key: keyPair.publicKey,
                deviceId: deviceId,
                signingKey: longTerm.signing
            )
        }

        let signedPublicKyberOneTimeKeys: [UserConfiguration.SignedPQKemOneTimeKey] = try kyberOneTimeKeyPairs.map { keyPair in
            try UserConfiguration.SignedPQKemOneTimeKey(
                key: keyPair.publicKey,
                deviceId: deviceId,
                signingKey: longTerm.signing
            )
        }

        // Create the user configuration with the signed device and keys
        let userConfiguration = UserConfiguration(
            signingPublicKey: longTerm.signing.publicKey.rawRepresentation,
            signedDevices: [signedDeviceConfiguration],
            signedOneTimePublicKeys: signedOneTimePublicKeys,
            signedPQKemOneTimePublicKeys: signedPublicKyberOneTimeKeys
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
    private func generateDatabaseEncryptionKey() -> Data {
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
    /// - Throws: An error of type `SessionErrors` if the session creation fails due to various reasons.
    public func createSession(
        secretName: String,
        appPassword: String,
        createInitialTransport: @Sendable @escaping () async throws -> Void
    ) async throws -> PQSSession {
        await setAppPassword(appPassword)
        let secretName = secretName.lowercased()
        // Ensure identity store is initialized
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        let bundle = try await createDeviceCryptographicBundle(isMaster: true)
        let sessionUser = SessionUser(
            secretName: secretName,
            deviceId: bundle.deviceKeys.deviceId,
            deviceKeys: bundle.deviceKeys,
            metadata: .init()
        )

        var sessionContext = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: generateDatabaseEncryptionKey(),
            sessionContextId: .random(in: 1 ..< .max),
            activeUserConfiguration: bundle.userConfiguration,
            registrationState: .unregistered
        )
        await setSessionContext(sessionContext)

        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
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
            throw SessionErrors.connectionIsNonViable
        }

        // Attempt to find user configuration and handle registration
        do {
            // We are registering a new device to the main device if this succeeds
            if try await transportDelegate?.findConfiguration(for: secretName) != nil {
                throw SessionErrors.userExists
            }

            // SHOULD NEVER HAPPEN
            throw SessionErrors.unknownError
        } catch let sessionError as SessionErrors {
            switch sessionError {
            case .userExists:
                throw sessionError

            case .userNotFound:
                // UserConfiguration does not contain Private keys/info... so it should be safe to store publicly.
                try await transportDelegate?.publishUserConfiguration(
                    bundle.userConfiguration,
                    recipient: bundle.deviceKeys.deviceId
                )

                sessionContext.registrationState = .registered
                await setSessionContext(sessionContext)

                let encodedData = try BSONEncoder().encodeData(sessionContext)
                guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: appSymmetricKey) else {
                    throw SessionErrors.sessionEncryptionError
                }

                // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
                try await cache.createLocalSessionContext(encryptedConfig)

                // Create Communication Model for personal messages
                self.logger.log(level: .debug, message: "Creating Communication Model")

                let communicationModel = try await taskProcessor.createCommunicationModel(
                    recipients: [secretName],
                    communicationType: .personalMessage,
                    metadata: [:],
                    symmetricKey: databaseEncryptionKey
                )

                guard var props = await communicationModel.props(symmetricKey: databaseEncryptionKey) else {
                    throw PQSSession.SessionErrors.propsError
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
        }
        return self
    }

    /// This call must be followed by start session.
    /// Links a device to the current session by generating cryptographic credentials.
    ///
    /// This asynchronous function links a new device to the current session by
    /// generating cryptographic credentials based on the provided device configuration
    /// and password. It creates a session identity, derives a symmetric key, and
    /// sets up the session context. It also creates a communication model for personal
    /// messages. This call must be followed by a call to `startSession`.
    ///
    /// - Parameters:
    ///   - bundle: A `CryptographicBundle` containing the device configuration and keys.
    ///   - password: A string representing the password used for cryptographic operations.
    ///
    /// - Throws:
    ///   - `SessionErrors.databaseNotInitialized`: If the cache is not initialized.
    ///   - `SessionErrors.appPasswordError`: If there is an error retrieving the password data.
    ///   - `SessionErrors.sessionEncryptionError`: If the session context cannot be encrypted successfully.
    ///   - `SessionErrors.registrationError`: If the device linking process fails.
    ///   - `PQSSession.SessionErrors.propsError`: If there is an error retrieving or updating properties in the communication model.
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
            finalPQKemPublicKey: .init(Data()),
            deviceName: bundle.deviceConfiguration.deviceName,
            hmacData: bundle.deviceConfiguration.hmacData,
            isMasterDevice: bundle.deviceConfiguration.isMasterDevice
        )

        // Encode the device configuration to prepare for QR code generation
        let data = try BSONEncoder().encodeData(linkConfig)

        // Generate cryptographic credentials for device linking
        if let credentials = await linkDelegate?.generateDeviceCryptographic(data, password: password) {
            guard let cache else {
                throw SessionErrors.databaseNotInitialized
            }

            // Set the application password from the generated credentials
            await setAppPassword(credentials.password)

            // Create a Session Identity
            let sessionUser = SessionUser(
                secretName: credentials.secretName,
                deviceId: bundle.deviceKeys.deviceId,
                deviceKeys: bundle.deviceKeys,
                metadata: .init()
            )

            // Generate a symmetric key for encrypting local database models
            let databaseEncryptionKey = generateDatabaseEncryptionKey()

            // Create a new user configuration with the provided device keys and configurations
            let userConfiguration = try await createNewUser(
                configuration: bundle.userConfiguration,
                signingPrivateKeyData: bundle.deviceKeys.signingPrivateKey,
                devices: credentials.devices,
                keys: bundle.userConfiguration.getVerifiedCurveKeys(deviceId: bundle.deviceKeys.deviceId),
                pqKemKeys: bundle.userConfiguration.getVerifiedPQKemKeys(deviceId: bundle.deviceKeys.deviceId)
            )

            // Create a new session context with the session user and user configuration
            var sessionContext = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: databaseEncryptionKey,
                sessionContextId: .random(in: 1 ..< .max),
                activeUserConfiguration: userConfiguration,
                registrationState: .unregistered
            )

            // Set the session context
            await setSessionContext(sessionContext)

            // Convert the password to data for deriving the symmetric key
            guard let passwordData = credentials.password.data(using: .utf8) else {
                throw SessionErrors.appPasswordError
            }

            // Retrieve salt and derive the symmetric key
            let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)
            let symmetricKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData
            )

            // Update the registration state to registered
            sessionContext.registrationState = .registered
            await setSessionContext(sessionContext)

            // Encode the updated session context for encryption
            let encodedData = try BSONEncoder().encode(sessionContext).makeData()

            // Encrypt the session context using the derived symmetric key
            guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
                throw SessionErrors.sessionEncryptionError
            }

            // Create a local session context with the encrypted data
            try await cache.createLocalSessionContext(encryptedConfig)

            // Create a communication model for personal messages
            logger.log(level: .debug, message: "Creating Communication Model")
            let databaseSymmetricKey = try await getDatabaseSymmetricKey()
            let communicationModel = try await taskProcessor.createCommunicationModel(
                recipients: [credentials.secretName],
                communicationType: .personalMessage,
                metadata: [:],
                symmetricKey: databaseSymmetricKey
            )

            // Update properties of the communication model
            guard var props = await communicationModel.props(symmetricKey: databaseSymmetricKey) else {
                throw PQSSession.SessionErrors.propsError
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
            return try await startSession(appPassword: credentials.password)
        } else {
            throw SessionErrors.registrationError
        }
    }

    /// Updates the user's configuration with new device configurations.
    ///
    /// This asynchronous function updates the user's configuration by incorporating
    /// new device configurations. It retrieves the current session context from the
    /// cache, decrypts it, creates a new user configuration with the updated devices,
    /// and then re-encrypts the session context before saving it back to the cache.
    ///
    /// - Parameter devices: An array of `UserDeviceConfiguration` objects representing
    ///                     the new devices to be associated with the user's configuration.
    ///
    /// - Throws:
    ///   - `SessionErrors.sessionDecryptionError`: If the session context cannot be
    ///     decrypted successfully.
    ///   - `PQSSession.SessionErrors.sessionEncryptionError`: If the updated session
    ///     context cannot be encrypted successfully.
    public func updateUserConfiguration(_ devices: [UserDeviceConfiguration]) async throws {
        // Retrieve the current session context from the cache
        guard let data = try await cache?.fetchLocalSessionContext() else { return }

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
        var sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))

        // Create a new user configuration with the updated devices
        let userConfiguration = try await createNewUser(
            configuration: sessionContext.activeUserConfiguration,
            signingPrivateKeyData: sessionContext.sessionUser.deviceKeys.signingPrivateKey,
            devices: devices,
            keys: sessionContext.activeUserConfiguration.getVerifiedCurveKeys(deviceId: sessionContext.sessionUser.deviceId),
            pqKemKeys: sessionContext.activeUserConfiguration.getVerifiedPQKemKeys(deviceId: sessionContext.sessionUser.deviceId)
        )

        // Update the last user configuration in the session context
        sessionContext.activeUserConfiguration = userConfiguration

        // Save the updated session context back to the cache
        await setSessionContext(sessionContext)

        // Encode the updated session context to prepare for encryption
        let encodedData = try BSONEncoder().encode(sessionContext).makeData()

        // Encrypt the updated session context using the app's symmetric key
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
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
    ///   - `SessionErrors.sessionDecryptionError`: If the session context cannot be
    ///     decrypted successfully.
    ///   - `PQSSession.SessionErrors.sessionEncryptionError`: If the updated session
    ///     context cannot be encrypted successfully.
    public func updateUseroneTimePublicKeys(_ keys: [UserConfiguration.SignedOneTimePublicKey]) async throws {
        // Retrieve the current session context from the cache
        guard let data = try await cache?.fetchLocalSessionContext() else { return }

        // Decrypt the session context data using the app's symmetric key
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        // Decode the session context from the decrypted data
        var sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))

        // Create a new UserConfiguration with the updated public one-time keys
        let userConfiguration = UserConfiguration(
            signingPublicKey: sessionContext.activeUserConfiguration.signingPublicKey,
            signedDevices: sessionContext.activeUserConfiguration.signedDevices,
            signedOneTimePublicKeys: keys,
            signedPQKemOneTimePublicKeys: sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys
        )

        // Update the last user configuration in the session context
        sessionContext.activeUserConfiguration = userConfiguration

        // Save the updated session context back to the cache
        await setSessionContext(sessionContext)

        // Encode the updated session context to prepare for encryption
        let encodedData = try BSONEncoder().encode(sessionContext).makeData()

        // Encrypt the updated session context using the app's symmetric key
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getAppSymmetricKey()) else {
            throw PQSSession.SessionErrors.sessionEncryptionError
        }

        // Update the local session context in the cache with the encrypted data
        try await cache?.updateLocalSessionContext(encryptedConfig)
    }

    /// Creates a new user configuration by signing device configurations and public keys.
    ///
    /// This asynchronous function takes a user configuration, a private signing key,
    /// a list of device configurations, and a list of public keys. It reconstructs the
    /// signing key, verifies the public signing key against the provided configuration,
    /// and signs each device configuration and public key with the private signing key.
    /// If any verification fails, an error is thrown.
    ///
    /// - Parameters:
    ///   - configuration: The initial user configuration containing the public signing key
    ///                    and a list of signed devices.
    ///   - signingPrivateKeyData: The raw data representation of the private signing key
    ///                            used for signing the device configurations and keys.
    ///   - devices: An array of `UserDeviceConfiguration` objects representing the devices
    ///              to be associated with the new user.
    ///   - keys: An array of `CurvePublicKey` objects representing the
    ///           public keys to be signed for the devices.
    ///
    /// - Throws:
    ///   - `PQSSession.SessionErrors.invalidSignature`: If the public signing key does
    ///     not match the reconstructed private signing key or if any device's signature
    ///     verification fails.
    ///
    /// - Returns: A new `UserConfiguration` object containing the public signing key,
    ///            signed device configurations, and signed public one-time keys.
    public func createNewUser(
        configuration: UserConfiguration,
        signingPrivateKeyData: Data,
        devices: [UserDeviceConfiguration],
        keys: [CurvePublicKey],
        pqKemKeys: [PQKemPublicKey]
    ) async throws -> UserConfiguration {
        // 1) Reconstruct your Curve25519 signing key
        let signingPrivateKey = try Curve25519SigningPrivateKey(
            rawRepresentation: signingPrivateKeyData
        )
        let signingPublicKey = try Curve25519SigningPublicKey(rawRepresentation: configuration.signingPublicKey)

        // Verify that the public signing key matches the reconstructed private signing key
        guard signingPublicKey.rawRepresentation == signingPrivateKey.publicKey.rawRepresentation else {
            throw PQSSession.SessionErrors.invalidSignature
        }

        // 2) Verify each signed device using the public signing key
        for device in configuration.signedDevices {
            if try (device.verified(using: signingPublicKey) != nil) == false {
                throw PQSSession.SessionErrors.invalidSignature
            }
        }

        // 3) For each device, build its SignedDeviceConfiguration
        let signedDevices: [UserConfiguration.SignedDeviceConfiguration] = try devices.map { device in
            try UserConfiguration.SignedDeviceConfiguration(
                device: device,
                signingKey: signingPrivateKey
            )
        }

        // Create signed public one-time keys for each device
        let signedKeys: [UserConfiguration.SignedOneTimePublicKey] = try devices.flatMap { device in
            try keys.map { key in
                try UserConfiguration.SignedOneTimePublicKey(
                    key: key,
                    deviceId: device.deviceId,
                    signingKey: signingPrivateKey
                )
            }
        }

        // Create signed public one-time keys for each device
        let signedKyberKeys: [UserConfiguration.SignedPQKemOneTimeKey] = try devices.flatMap { device in
            try pqKemKeys.map { key in
                try UserConfiguration.SignedPQKemOneTimeKey(
                    key: key,
                    deviceId: device.deviceId,
                    signingKey: signingPrivateKey
                )
            }
        }

        // 4) Return the new per-device-signed UserConfiguration
        return UserConfiguration(
            signingPublicKey: signingPublicKey.rawRepresentation,
            signedDevices: signedDevices,
            signedOneTimePublicKeys: signedKeys,
            signedPQKemOneTimePublicKeys: signedKyberKeys
        )
    }

    /// Starts a session using the provided application password.
    ///
    /// This method retrieves the local device salt, derives a symmetric key from the application password,
    /// and attempts to decrypt the local device configuration. If successful, it updates the last user
    /// configuration and returns a shared `PQSSession`.
    ///
    /// - Parameters:
    ///   - appPassword: The application password used for encryption and session management.
    /// - Returns: A `PQSSession` object representing the started session.
    /// - Throws: An error of type `SessionErrors` if the session start fails due to various reasons.
    public func startSession(appPassword: String) async throws -> PQSSession {
        await setAppPassword(appPassword)
        // Ensure the identity store is initialized
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        // Retrieve the local device configuration
        let data = try await cache.fetchLocalSessionContext()

        // Convert the application password to Data
        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.saltError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        // Derive the symmetric key from the password and salt - This is the AppSymmetricKey
        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        do {
            // Decrypt the configuration data
            guard let configurationData = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
                throw SessionErrors.sessionDecryptionError
            }

            // Decode the session context from the decrypted data
            let sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
            await setSessionContext(sessionContext)
            return self
        } catch {
            throw error
        }
    }

    private func removeExpiredOTKeys() {
        refreshOTKeysTask = nil
    }

    private func removeExpiredKyberOTKeys() {
        refreshKyberOTKeysTask = nil
    }

    public func refreshOneTimeKeysTask() async {
        // Cancel any existing task before creating a new one
        refreshOTKeysTask?.cancel()

        refreshOTKeysTask = Task(executorPreference: taskProcessor.keyTransportExecutor) { [weak self] in
            guard let self else { return }

            do {
                try await refreshOneTimeKeys(refreshType: .curve)
            } catch {
                // Handle any errors that may occur during the refresh
                await logger.log(level: .error, message: "Error refreshing one-time keys: \(error)")
            }

            // Clean up the task reference after completion
            await removeExpiredOTKeys()
        }
    }

    public func refreshKyberOneTimeKeysTask() async {
        // Cancel any existing task before creating a new one
        refreshKyberOTKeysTask?.cancel()

        refreshKyberOTKeysTask = Task(executorPreference: taskProcessor.keyTransportExecutor) { [weak self] in
            guard let self else { return }

            do {
                try await refreshOneTimeKeys(refreshType: .kyber)
            } catch {
                // Handle any errors that may occur during the refresh
                await logger.log(level: .error, message: "Error refreshing one-time keys: \(error)")
            }

            // Clean up the task reference after completion
            await removeExpiredKyberOTKeys()
        }
    }

    func refreshOneTimeKeys(refreshType: KeysType) async throws {
        guard let sessionContext = await sessionContext else { return }
        guard let cache else { return }
        var keys = [UUID]()

        if let fetched = try await transportDelegate?.fetchOneTimeKeyIdentities(for: sessionContext.sessionUser.secretName, deviceId: sessionContext.sessionUser.deviceId.uuidString, type: refreshType) {
            keys = fetched
        }

        if !keys.isEmpty {
            let publicKeysCount = try await synchronizeLocalKeys(cache: cache, keys: keys, type: refreshType)
            if publicKeysCount <= 10 {
                // 1. Delete all local keys that are not on the server
                let config = try await cache.fetchLocalSessionContext()

                // Decrypt the session context data using the app's symmetric key
                guard let configurationData = try await crypto.decrypt(data: config, symmetricKey: getAppSymmetricKey()) else {
                    throw SessionErrors.sessionDecryptionError
                }

                // Decode the session context from the decrypted data
                var sessionContext = try BSONDecoder().decodeData(SessionContext.self, from: configurationData)

                logger.log(level: .info, message: "Creating Key Pairs, count: \(100 - publicKeysCount)")
                switch refreshType {
                case .curve:
                    // Create needed key pairs
                    let privateOneTimeKeyPairs: [KeyPair] = try (0 ..< 100 - publicKeysCount).map { _ in
                        let id = UUID()
                        let privateKey = crypto.generateCurve25519PrivateKey()
                        let privateKeyRep = try CurvePrivateKey(id: id, privateKey.rawRepresentation)
                        let publicKey = try CurvePublicKey(id: id, privateKey.publicKey.rawRepresentation)
                        return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
                    }

                    sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.append(contentsOf: privateOneTimeKeyPairs.map(\.privateKey))
                    let signedOneTimePublicKeys: [UserConfiguration.SignedOneTimePublicKey] = try privateOneTimeKeyPairs.map { keyPair in
                        try UserConfiguration.SignedOneTimePublicKey(
                            key: keyPair.publicKey,
                            deviceId: sessionContext.sessionUser.deviceId,
                            signingKey: Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey)
                        )
                    }

                    sessionContext.activeUserConfiguration.signedOneTimePublicKeys.append(contentsOf: signedOneTimePublicKeys)

                    try await transportDelegate?.updateOneTimeKeys(
                        for: sessionContext.sessionUser.secretName,
                        deviceId: sessionContext.sessionUser.deviceId.uuidString,
                        keys: signedOneTimePublicKeys
                    )

                case .kyber:
                    // Create needed key pairs
                    let kyberOneTimeKeyPairs: [KeyPair] = try (0 ..< 100).map { _ in
                        let id = UUID()
                        let privateKey = try crypto.generateKyber1024PrivateSigningKey()
                        let privateKeyRep = try PQKemPrivateKey(id: id, privateKey.encode())
                        let publicKey = try PQKemPublicKey(id: id, privateKey.publicKey.rawRepresentation)
                        return KeyPair(id: id, publicKey: publicKey, privateKey: privateKeyRep)
                    }

                    sessionContext.sessionUser.deviceKeys.pqKemOneTimePrivateKeys.append(contentsOf: kyberOneTimeKeyPairs.map(\.privateKey))
                    let signedKyberOneTimeKeys: [UserConfiguration.SignedPQKemOneTimeKey] = try kyberOneTimeKeyPairs.map { keyPair in
                        try UserConfiguration.SignedPQKemOneTimeKey(
                            key: keyPair.publicKey,
                            deviceId: sessionContext.sessionUser.deviceId,
                            signingKey: Curve25519.Signing.PrivateKey(rawRepresentation: sessionContext.sessionUser.deviceKeys.signingPrivateKey)
                        )
                    }

                    sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys.append(contentsOf: signedKyberOneTimeKeys)

                    try await transportDelegate?.updateOneTimePQKemKeys(
                        for: sessionContext.sessionUser.secretName,
                        deviceId: sessionContext.sessionUser.deviceId.uuidString,
                        keys: signedKyberOneTimeKeys
                    )
                }

                sessionContext.updateSessionUser(sessionContext.sessionUser)
                await setSessionContext(sessionContext)

                // Encrypt and persist
                let encodedData = try BSONEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData.makeData(), symmetricKey: getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }

                try await cache.updateLocalSessionContext(encryptedConfig)
            }
        }
    }

    func synchronizeLocalKeys(cache: SessionCache, keys: [UUID], type: KeysType) async throws -> Int {
        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }

        var sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
        var didUpdate = false

        switch type {
        case .curve:
            let privateKeys = sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys
            let publicKeys = sessionContext.activeUserConfiguration.signedOneTimePublicKeys
            let privateKeyIDs = Set(privateKeys.map(\.id))
            let publicKeyIDs = Set(publicKeys.map(\.id))
            let remoteKeySet = Set(keys)

            let privateIntersection = privateKeyIDs.intersection(remoteKeySet)
            let publicIntersection = publicKeyIDs.intersection(remoteKeySet)

            if privateIntersection.isEmpty, publicIntersection.isEmpty {
                // No shared keys — remove all
                sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.removeAll()
                sessionContext.activeUserConfiguration.signedOneTimePublicKeys.removeAll()
                didUpdate = true
            } else {
                // Remove only keys not in remote list
                let filteredPrivate = privateKeys.filter { remoteKeySet.contains($0.id) }
                if filteredPrivate.count != privateKeys.count {
                    sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys = filteredPrivate
                    didUpdate = true
                }

                let filteredPublic = publicKeys.filter { remoteKeySet.contains($0.id) }
                if filteredPublic.count != publicKeys.count {
                    sessionContext.activeUserConfiguration.signedOneTimePublicKeys = filteredPublic
                    didUpdate = true
                }
            }

            if didUpdate {
                sessionContext.updateSessionUser(sessionContext.sessionUser)
                await setSessionContext(sessionContext)

                let encodedData = try BSONEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData.makeData(), symmetricKey: getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }

                try await cache.updateLocalSessionContext(encryptedConfig)

                // if we have no keys delete all public keys on the server so we can regenerated a fresh batch
                if sessionContext.sessionUser.deviceKeys.oneTimePrivateKeys.isEmpty || sessionContext.activeUserConfiguration.signedOneTimePublicKeys.isEmpty {
                    try await transportDelegate?.batchDeleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: sessionContext.sessionUser.deviceId.uuidString, type: type)
                }
            }
            return sessionContext.activeUserConfiguration.signedOneTimePublicKeys.count
        case .kyber:
            let privateKeys = sessionContext.sessionUser.deviceKeys.pqKemOneTimePrivateKeys
            let publicKeys = sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys
            let privateKeyIDs = Set(privateKeys.map(\.id))
            let publicKeyIDs = Set(publicKeys.map(\.id))
            let remoteKeySet = Set(keys)

            let privateIntersection = privateKeyIDs.intersection(remoteKeySet)
            let publicIntersection = publicKeyIDs.intersection(remoteKeySet)

            if privateIntersection.isEmpty, publicIntersection.isEmpty {
                // No shared keys — remove all
                sessionContext.sessionUser.deviceKeys.pqKemOneTimePrivateKeys.removeAll()
                sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys.removeAll()
                didUpdate = true
            } else {
                // Remove only keys not in remote list
                let filteredPrivate = privateKeys.filter { remoteKeySet.contains($0.id) }
                if filteredPrivate.count != privateKeys.count {
                    sessionContext.sessionUser.deviceKeys.pqKemOneTimePrivateKeys = filteredPrivate
                    didUpdate = true
                }

                let filteredPublic = publicKeys.filter { remoteKeySet.contains($0.id) }
                if filteredPublic.count != publicKeys.count {
                    sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys = filteredPublic
                    didUpdate = true
                }
            }

            if didUpdate {
                sessionContext.updateSessionUser(sessionContext.sessionUser)
                await setSessionContext(sessionContext)

                let encodedData = try BSONEncoder().encode(sessionContext)
                guard let encryptedConfig = try await crypto.encrypt(data: encodedData.makeData(), symmetricKey: getAppSymmetricKey()) else {
                    throw PQSSession.SessionErrors.sessionEncryptionError
                }

                try await cache.updateLocalSessionContext(encryptedConfig)

                // if we have no keys delete all public keys on the server so we can regenerated a fresh batch
                if sessionContext.sessionUser.deviceKeys.pqKemOneTimePrivateKeys.isEmpty || sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys.isEmpty {
                    try await transportDelegate?.batchDeleteOneTimeKeys(for: sessionContext.sessionUser.secretName, with: sessionContext.sessionUser.deviceId.uuidString, type: type)
                }
            }
            return sessionContext.activeUserConfiguration.signedPQKemOneTimePublicKeys.count
        }
    }

    /// Retrieves the symmetric key for database encryption.
    public func getDatabaseSymmetricKey() async throws -> SymmetricKey {
        guard let data = await sessionContext?.databaseEncryptionKey else {
            throw SessionErrors.sessionNotInitialized
        }
        return SymmetricKey(data: data)
    }

    /// Derives the symmetric key from the application password.
    public func getAppSymmetricKey() async throws -> SymmetricKey {
        guard let passwordData = await appPassword.data(using: .utf8) else {
            throw SessionErrors.invalidPassword
        }

        // Retrieve salt and derive symmetric key
        guard let saltData = try await cache?.fetchLocalDeviceSalt(keyData: passwordData) else { throw SessionErrors.saltError }

        return await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )
    }

    /// Verifies an input password against stored session context.
    public func verifyAppPassword(_ appPassword: String) async -> Bool {
        do {
            guard let passwordData = appPassword.data(using: .utf8) else {
                throw SessionErrors.invalidPassword
            }

            guard let saltData = try await cache?.fetchLocalDeviceSalt(keyData: passwordData) else { throw SessionErrors.saltError }

            let appEncryptionKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData
            )

            await setAppPassword(appPassword)

            guard let data = try await cache?.fetchLocalSessionContext() else { return false }
            let box = try AES.GCM.SealedBox(combined: data)
            _ = try AES.GCM.open(box, using: appEncryptionKey)
            return true
        } catch {
            return false
        }
    }

    /// Changes the application password and re-encrypts the session context.
    public func changeAppPassword(_ newPassword: String) async throws {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }

        let data = try await cache.fetchLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }
        // Decode the session context from the decrypted data
        let sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
        try await cache.deleteLocalDeviceSalt()

        guard let passwordData = newPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
        }

        // Retrieve salt and derive symmetric key
        let saltData = try await cache.fetchLocalDeviceSalt(keyData: passwordData)

        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData
        )

        let encodedData = try BSONEncoder().encodeData(sessionContext)
        guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
            throw SessionErrors.sessionEncryptionError
        }

        await setAppPassword(newPassword)

        // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
        try await cache.updateLocalSessionContext(encryptedConfig)
    }

    /// Resumes processing of any pending tasks in the queue.
    public func resumeJobQueue() async throws {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        try await taskProcessor.loadTasks(
            nil,
            cache: cache,
            symmetricKey: getDatabaseSymmetricKey(),
            session: self
        )
    }

    /// Shuts down the session, clearing sensitive state.
    public func shutdown() async {
        do {
            try await taskProcessor.ratchetManager.shutdown()
        } catch {
            fatalError("Could not shutdown ratchet manager: \(error)")
        }
        isViable = false
        cache = nil
        transportDelegate = nil
        receiverDelegate = nil
        linkDelegate = nil
        _sessionContext = nil
        _appPassword = ""
        await setDatabaseDelegate(conformer: nil)
        await setTransportDelegate(conformer: nil)
        setReceiverDelegate(conformer: nil)
        await setPQSSessionDelegate(conformer: nil)
        await setSessionEventDelegate(conformer: nil)
        sessionIdentities.removeAll()
    }

    #if os(iOS)
        private func getModelIdentifier() -> String {
            var systemInfo = utsname()
            uname(&systemInfo)

            // Use Mirror to access the machine field and convert it to a String
            let machineMirror = Mirror(reflecting: systemInfo.machine)
            let identifier = machineMirror.children.reduce("") { identifier, element in
                guard let value = element.value as? Int8, value != 0 else { return identifier }
                return identifier + String(UnicodeScalar(UInt8(value)))
            }

            return identifier
        }

    #elseif os(macOS)
        private func getModelIdentifier() -> String {
            var size = 0
            sysctlbyname("hw.model", nil, &size, nil, 0)

            var model = [CChar](repeating: 0, count: size)
            sysctlbyname("hw.model", &model, &size, nil, 0)

            let data = Data(bytes: model, count: size)
            return String(data: data, encoding: .utf8) ?? "Uknown Model"
        }

    #endif

    public func getDeviceName() -> String {
        #if os(iOS) || os(macOS)
            let modelIdentifier = getModelIdentifier()

            // Mapping of model identifiers to friendly names
            let deviceNames: [String: String] = [
                // iPhones
                "iPhone11,2": "iPhone XS",
                "iPhone11,4": "iPhone XS Max",
                "iPhone11,6": "iPhone XS Max Global",
                "iPhone11,8": "iPhone XR",
                "iPhone12,1": "iPhone 11",
                "iPhone12,3": "iPhone 11 Pro",
                "iPhone12,5": "iPhone 11 Pro Max",
                "iPhone12,8": "iPhone SE 2nd Gen",
                "iPhone13,1": "iPhone 12 Mini",
                "iPhone13,2": "iPhone 12",
                "iPhone13,3": "iPhone 12 Pro",
                "iPhone13,4": "iPhone 12 Pro Max",
                "iPhone14,2": "iPhone 13 Pro",
                "iPhone14,3": "iPhone 13 Pro Max",
                "iPhone14,4": "iPhone 13 Mini",
                "iPhone14,5": "iPhone 13",
                "iPhone14,6": "iPhone SE 3rd Gen",
                "iPhone14,7": "iPhone 14",
                "iPhone14,8": "iPhone 14 Plus",
                "iPhone15,2": "iPhone 14 Pro",
                "iPhone15,3": "iPhone 14 Pro Max",
                "iPhone15,4": "iPhone 15",
                "iPhone15,5": "iPhone 15 Plus",
                "iPhone16,1": "iPhone 15 Pro",
                "iPhone16,2": "iPhone 15 Pro Max",
                "iPhone17,1": "iPhone 16 Pro",
                "iPhone17,2": "iPhone 16 Pro Max",
                "iPhone17,3": "iPhone 16",
                "iPhone17,4": "iPhone 16 Plus",

                // iPads
                "iPad11,1": "iPad mini 5th Gen (WiFi)",
                "iPad11,2": "iPad mini 5th Gen (WiFi+Cellular)",
                "iPad11,3": "iPad Air 3rd Gen (WiFi)",
                "iPad11,4": "iPad Air 3rd Gen (WiFi+Cellular)",
                "iPad11,6": "iPad 8th Gen (WiFi)",
                "iPad11,7": "iPad 8th Gen (WiFi+Cellular)",
                "iPad12,1": "iPad 9th Gen (WiFi)",
                "iPad12,2": "iPad 9th Gen (WiFi+Cellular)",
                "iPad14,1": "iPad mini 6th Gen (WiFi)",
                "iPad14,2": "iPad mini 6th Gen (WiFi+Cellular)",
                "iPad13,1": "iPad Air 4th Gen (WiFi)",
                "iPad13,2": "iPad Air 4th Gen (WiFi+Cellular)",
                "iPad13,4": "iPad Pro 11 inch 5th Gen",
                "iPad13,5": "iPad Pro 11 inch 5th Gen",
                "iPad13,6": "iPad Pro 11 inch 5th Gen",
                "iPad13,7": "iPad Pro 11 inch 5th Gen",
                "iPad13,8": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,9": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,10": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,11": "iPad Pro 12.9 inch 5th Gen",
                "iPad13,16": "iPad Air 5th Gen (WiFi)",
                "iPad13,17": "iPad Air 5th Gen (WiFi+Cellular)",
                "iPad13,18": "iPad 10th Gen",
                "iPad13,19": "iPad 10th Gen",
                "iPad14,3": "iPad Pro 11 inch 4th Gen",
                "iPad14,4": "iPad Pro 11 inch 4th Gen",
                "iPad14,5": "iPad Pro 12.9 inch 6th Gen",
                "iPad14,6": "iPad Pro 12.9 inch 6th Gen",
                "iPad14,8": "iPad Air 6th Gen",
                "iPad14,9": "iPad Air 6th Gen",
                "iPad14,10": "iPad Air 7th Gen",
                "iPad14,11": "iPad Air 7th Gen",
                "iPad16,1": "iPad mini 7th Gen (WiFi)",
                "iPad16,2": "iPad mini 7th Gen (WiFi+Cellular)",
                "iPad16,3": "iPad Pro 11 inch 5th Gen",
                "iPad16,4": "iPad Pro 11 inch 5th Gen",
                "iPad16,5": "iPad Pro 12.9 inch 7th Gen",
                "iPad16,6": "iPad Pro 12.9 inch 7th Gen",

                // Macs
                // iMac (2019 and later)
                "iMac19,1": "iMac (2019)",
                "iMac19,2": "iMac (2019)",
                "iMac20,1": "iMac (2020)",
                "iMac21,1": "iMac (2021)",

                // iMac Pro
                "iMacPro1,1": "iMac Pro (2017)",

                // MacBook Air (2020 and later)
                "MacBookAir8,1": "MacBook Air (Retina, 2018)",
                "MacBookAir9,1": "MacBook Air (M1, 2020)",
                "Mac14,7": "MacBook Air (2023)",

                // MacBook Pro (2017 and later)
                "MacBookPro14,1": "MacBook Pro (2017)",
                "MacBookPro14,3": "MacBook Pro (2017)",
                "MacBookPro15,1": "MacBook Pro (2019)",
                "MacBookPro16,1": "MacBook Pro (2021)",
                "MacBookPro18,1": "MacBook Pro (2021)",
                "MacBookPro18,3": "MacBook Pro (2021)",
                "MacBookPro18,2": "MacBook Pro (M1, 2020)",
                "Mac14,8": "MacBook Air/Pro (M2, 2023)",
                "Mac14,9": "MacBook Pro (M2, 2023)",
                "Mac16,5": "MacBook Pro (M4 Max 2024)",

                // Mac Pro (2019 and later)
                "MacPro7,1": "Mac Pro (2019)",

                // Mac Studio (2022 and later)
                "Mac13,1": "Mac Studio (2022)",

                // Mac mini (2018 and later)
                "Macmini8,1": "Mac mini (2018)",
                "Macmini9,1": "Mac mini (M1, 2020)",
                "Mac14,4": "Mac mini (M2, 2022)",
            ]

            return deviceNames[modelIdentifier] ?? modelIdentifier
        #else
            return "Unkown Device Model"
        #endif
    }
}
