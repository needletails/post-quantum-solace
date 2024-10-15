//
//  NeedleTailSession.swift
//  needletail-crypto
//
//  Created by Cole M on 9/12/24.
//
//import NeedleTailStructures
import Foundation
import BSON
import NeedleTailHelpers
import NeedleTailCrypto
@preconcurrency import Crypto

public enum RegistrationState: Codable, Sendable {
    case registered, unregistered
}

public actor CryptoSession: NetworkDelegate, SessionCacheSynchronizer {
    
    nonisolated let id = UUID()
    // Indicates if the session is viable for operations
    nonisolated(unsafe) public var isViable: Bool = false
    
    // Singleton instance of CryptoSession
    public static let shared = CryptoSession()
    init() {}
    
    private let crypto = NeedleTailCrypto()
    let taskProcessor = TaskProcessor()
    public var cache: SessionCache?
    internal var transportDelegate: SessionTransport?
    internal var receiverDelegate: NTMessageReceiver?
    private(set) internal var _sessionContext: SessionContext?
    private var _appPassword = ""
    public var sessionContext: SessionContext? {
        get async {
            _sessionContext
        }
    }
    func setSessionContext(_ context: SessionContext) async {
        _sessionContext = context
    }
    
    public var appPassword: String {
        get async {
            _appPassword
        }
    }
    
    func setAppPassword(_ password: String) {
        _appPassword = password
    }

    nonisolated func synchronizeLocalConfiguration(_ data: Data) {
        Task { [weak self] in
            guard let self else { return }
            let symmetricKey = try await self.getAppSymmetricKey(password: appPassword)
            guard let decryptedData = try self.crypto.decrypt(data: data, symmetricKey: symmetricKey) else { return }
            let context = try BSONDecoder().decodeData(SessionContext.self, from: decryptedData)
            await setSessionContext(context)
        }
    }
    
    /// Sets the transport delegate conforming to `SessionTransport`.
    /// - Parameter conformer: The conforming object to set as the transport delegate.
    public func setTransportDelegate(conformer: SessionTransport?) {
        transportDelegate = conformer
    }
    
    /// Sets the database delegate conforming to `IdentityStore`.
    /// - Parameter conformer: The conforming object to set as the identity store.
    public func setDatabaseDelegate(conformer: CryptoSessionStore?) {
        if let conformer = conformer {
            cache = SessionCache(store: conformer)
        }
    }
    
    public func setReceiverDelegate(conformer: NTMessageReceiver?) {
        receiverDelegate = conformer
    }
    
    public enum SessionErrors: Error {
        case saltError
        case databaseNotInitialized
        case sessionNotInitialized
        case transportNotInitialized
        case sessionEncryptionError
        case sessionDecryptionError
        case connectionIsNonViable
        case invalidPassword
        case invalidSecretName
        case missingSessionIdentity
        case invalidSignature
        case missingSignature
        case configurationError
        case cannotFindCommunication
        case cannotFindContact
        case propsError
        case appPasswordError
        case missingKey
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
    /// - Returns: A `CryptoSession` object representing the created session.
    /// - Throws: An error of type `SessionErrors` if the session creation fails due to various reasons.
    public func createSession(
        secretName: String,
        appPassword: String
    ) async throws -> CryptoSession {
        
        // Ensure identity store is initialized
        guard let cache = cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        // Create database symmetric key
        let databaseSymmetricKey = SymmetricKey(size: .bits256)
        let databaseEncryptionKey = databaseSymmetricKey.withUnsafeBytes { Data($0) }
        
        // Create User/Identity key that represents this device
        let privateKey = crypto.generateCurve25519PrivateKey()
        let privateSigningKey = crypto.generateCurve25519SigningPrivateKey()
        let deviceIdentity = UUID()
        
        let deviceKeys = DeviceKeys(
            deviceIdentity: deviceIdentity,
            privateSigningKey: privateSigningKey.rawRepresentation,
            privateKey: privateKey.rawRepresentation)
        
        let sessionUser = SessionUser(
            secretName: secretName,
            deviceIdentity: deviceIdentity,
            deviceKeys: deviceKeys)

        let device = try UserDeviceConfiguration(
            deviceIdentity: deviceKeys.deviceIdentity,
            publicSigningKey: privateSigningKey.publicKey.rawRepresentation,
            publicKey: privateKey.publicKey.rawRepresentation,
            isMasterDevice: true)
        
        let userConfiguration = try UserConfiguration(
            publicSigningKey: privateSigningKey.publicKey.rawRepresentation,
            devices: [device],
            privateSigningKey: privateSigningKey)
        
        var sessionContext = SessionContext(
            sessionUser: sessionUser,
            databaseEncryptionKey: databaseEncryptionKey,
            sessionContextId: .random(in: 1 ..< .max),
            lastUserConfiguration: userConfiguration,
            registrationState: .unregistered)
        await setSessionContext(sessionContext)
        
        // Retrieve salt and derive symmetric key
        let salt = try await cache.findLocalDeviceSalt()
        guard let saltData = salt.data(using: .utf8) else {
            throw SessionErrors.saltError
        }
        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
        }
        
        let appSymmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
        
        // Check if the connection is viable
        guard isViable else {
            throw SessionErrors.connectionIsNonViable
        }
        
        // Attempt to find user configuration and handle registration
        do {
            //We are registering a new device to the main device if this succeeds
            let configuration = try await transportDelegate?.findConfiguration(for: secretName)
            sessionContext.registrationState = .registered
            
            let encodedData = try BSONEncoder().encode(sessionContext).makeData()
            guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: appSymmetricKey) else {
                throw SessionErrors.sessionEncryptionError
            }
            
            // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
            try await cache.createLocalDeviceConfiguration(encryptedConfig)
            
            let deviceKeyPublicSigningKey = try Curve25519SigningPrivateKey(rawRepresentation: deviceKeys.privateKey)
            if configuration?.publicSigningKey == deviceKeyPublicSigningKey.publicKey.rawRepresentation {
                return try await startSession(appPassword: appPassword)
            }
            
            let auxillaryConfiguration = try UserDeviceConfiguration(
                deviceIdentity: deviceKeys.deviceIdentity,
                publicSigningKey: deviceKeyPublicSigningKey.publicKey.rawRepresentation,
                publicKey: privateKey.publicKey.rawRepresentation,
                isMasterDevice: false)
            
            // auxillaryConfiguration does not contain Private keys/info... so it should be safe to store publicly.
            // this is used to share the UserDeviceConfiguration to another device. Like via a QR Code.
            try await transportDelegate?.publishAuxillary(configuration: auxillaryConfiguration)
            return try await startSession(appPassword: appPassword)
            
        } catch {
            //Registering a new account(device)
            // Handle errors and ensure session context is registered
            sessionContext.registrationState = .registered
            let encodedData = try BSONEncoder().encodeData(sessionContext)
            guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: appSymmetricKey) else {
                throw SessionErrors.sessionEncryptionError
            }
            
            // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
            try await cache.createLocalDeviceConfiguration(encryptedConfig)
            // UserConfiguration does not contain Private keys/info... so it should be safe to store publicly.
            try await transportDelegate?.publishUserConfiguration(userConfiguration, identity: nil)
            
            return try await startSession(appPassword: appPassword)
        }
    }
    
    /// Starts a session using the provided application password.
    ///
    /// This method retrieves the local device salt, derives a symmetric key from the application password,
    /// and attempts to decrypt the local device configuration. If successful, it updates the last user
    /// configuration and returns a shared `CryptoSession`.
    ///
    /// - Parameters:
    ///   - appPassword: The application password used for encryption and session management.
    /// - Returns: A `CryptoSession` object representing the started session.
    /// - Throws: An error of type `SessionErrors` if the session start fails due to various reasons.
    public func startSession(appPassword: String) async throws -> CryptoSession {
        
        // Ensure the identity store is initialized
        guard let cache = cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        // Retrieve the local device salt
        let salt = try await cache.findLocalDeviceSalt()
        guard let saltData = salt.data(using: .utf8) else {
            throw SessionErrors.saltError
        }
        
        // Convert the application password to Data
        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.saltError
        }
        
        // Derive the symmetric key from the password and salt
        let appSymmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
        
        // Retrieve the local device configuration
        let data = try await cache.findLocalDeviceConfiguration()
        
        do {
            // Decrypt the configuration data
            guard let configurationData = try crypto.decrypt(data: data, symmetricKey: appSymmetricKey) else {
                throw SessionErrors.sessionDecryptionError
            }
            
            // Decode the session context from the decrypted data
            let sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
            
            setAppPassword(appPassword)
            await setSessionContext(sessionContext)
            return CryptoSession.shared
        } catch {
            throw error
        }
    }
    
    func createAppSymmetricKey(passwordData: Data, saltData: Data) async -> SymmetricKey {
        await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
    }
    
    public func getAppSymmetricKey(password: String) async throws -> SymmetricKey {
        guard let salt = try await cache?.findLocalDeviceSalt() else { throw SessionErrors.saltError }
        guard let passwordData = await appPassword.data(using: .utf8) else {
            throw SessionErrors.invalidPassword
        }
        guard let saltData = salt.data(using: .utf8) else {
            throw SessionErrors.saltError
        }
        return await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
    }
    
    public func verifyAppPassword(_ appPassword: String) async -> Bool {
        do {
            let salt = try await self.cache?.findLocalDeviceSalt()
            let appEncryptionKey = try await getAppSymmetricKey(password: appPassword)
            guard let data = try await self.cache?.findLocalDeviceConfiguration() else { return false }
            let box = try AES.GCM.SealedBox(combined: data)
            _ = try AES.GCM.open(box, using: appEncryptionKey)
            return true
        } catch {
            return false
        }
    }
    
    public func loadSessionContextCache() async throws {
        guard let transportDelegate = transportDelegate else { return }
        
        // If we published auxiallary device on the server. we need to make sure we know about them so...
        //1. find the current user session context on the server
        guard var sessionContext = await sessionContext else { return }
        let configuration = try await transportDelegate.findConfiguration(for: sessionContext.sessionUser.secretName)

        //2. seach and discover if the current sessionContext matches the one we found on the server
        if sessionContext.lastUserConfiguration.signed?.data == configuration.signed?.data  {
            // do nothing
        } else {
            //3. make sure that the identities of the user configuration are legit
            let publicSigningKey = try Curve25519SigningPublicKey(rawRepresentation: configuration.publicSigningKey)
            if try configuration.signed?.verifySignature(publicKey: publicSigningKey) == false {
                throw SigningErrors.signingFailedOnVerfication
            }
            //4. save/update locally and cache
            sessionContext.lastUserConfiguration = configuration
            let encodedData = try BSONEncoder().encodeData(sessionContext)
            guard let encryptedConfig = try await crypto.encrypt(
                data: encodedData,
                symmetricKey: getAppSymmetricKey(password: self.appPassword)) else {
                throw SessionErrors.sessionEncryptionError
            }
            try await cache?.updateLocalDeviceConfiguration(encryptedConfig)
        }
    }
}
