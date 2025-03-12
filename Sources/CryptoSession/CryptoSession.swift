//
//  NeedleTailSession.swift
//  needletail-crypto
//
//  Created by Cole M on 9/12/24.
//

import Foundation
import BSON
import NeedleTailCrypto
import NeedleTailLogger
@preconcurrency import Crypto
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

public enum RegistrationState: Codable, Sendable {
    case registered, unregistered
}

public struct LinkDeviceInfo: Sendable {
    public let secretName: String
    public let devices: [UserDeviceConfiguration]
    public let password: String
    
    public init(
        secretName: String,
        devices: [UserDeviceConfiguration],
        password: String
    ) {
        self.secretName = secretName
        self.devices = devices
        self.password = password
    }
}

public protocol DeviceLinkingDelegate: AnyObject, Sendable {
    func generatedDeviceCryptographic(_ data: Data, password: String) async -> LinkDeviceInfo?
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
    let logger = NeedleTailLogger(.init(label: "[CryptoSession]"))
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

    public func setSessionContext(_ context: SessionContext) async {
        _sessionContext = context
    }
    
    public var appPassword: String {
        get async {
            _appPassword
        }
    }
    
    func setAppPassword(_ password: String) async {
        _appPassword = password
    }
    
    func synchronizeLocalConfiguration(_ data: Data) async throws {
        let symmetricKey = try await self.getAppSymmetricKey()
        guard let decryptedData = try self.crypto.decrypt(data: data, symmetricKey: symmetricKey) else { return }
        let context = try BSONDecoder().decodeData(SessionContext.self, from: decryptedData)
        await setSessionContext(context)
    }
    
    /// Sets the transport delegate conforming to `SessionTransport`.
    /// - Parameter conformer: The conforming object to set as the transport delegate.
    public func setTransportDelegate(conformer: SessionTransport?) {
        transportDelegate = conformer
    }
    
    /// Sets the database delegate conforming to `IdentityStore`.
    /// - Parameter conformer: The conforming object to set as the identity store.
    public func setDatabaseDelegate(conformer: CryptoSessionStore?) async {
        if let conformer = conformer {
            cache = SessionCache(store: conformer)
            await cache?.setSynchronizer(self)
        }
    }
    
    public func setReceiverDelegate(conformer: NTMessageReceiver?) {
        receiverDelegate = conformer
    }
    
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
        case unknownError = "An unknown error occurred."
        case missingAuthInfo = "Missing authentication information in the payload"
        case userNotFound = "Could not find the user requested"
        case accessDenied = "Denied Access to the requested resource"
        case userIsBlocked = "The User is Blocked, cannot request friendship changes"
    }
    
    public struct CryptographicBundle: Sendable {
        public let deviceKeys: DeviceKeys
        let deviceConfiguration: UserDeviceConfiguration
        let userConfiguration: UserConfiguration
    }
    
    // We only need UserDeviceConfiguration object which is nested into the user configuration of key publishing we send this info to the server with an identifier, in our case this is a secretName. We can generate these keys for child device creation and present the data as a QRCode that the master device scans along with the child devices' deviceId along with the secret name from the master device. Whe then publish it to the server. We then need to send a message to the child device to register their session identity and then start the session. Publishing Child Devices should happen from the master device if we publish keys this way.
    public func createDeviceCryptographicBundle(isMaster: Bool) async throws -> CryptographicBundle {
        
        let privateKey = crypto.generateCurve25519PrivateKey()
        let privateSigningKey = crypto.generateCurve25519SigningPrivateKey()
        let deviceId = UUID()
        
        let deviceKeys = DeviceKeys(
            deviceId: deviceId,
            privateSigningKey: privateSigningKey.rawRepresentation,
            privateKey: privateKey.rawRepresentation)
        
        
        let device = try await UserDeviceConfiguration(
            deviceId: deviceKeys.deviceId,
            publicSigningKey: privateSigningKey.publicKey.rawRepresentation,
            publicKey: privateKey.publicKey.rawRepresentation,
            deviceName: getDeviceName(),
            isMasterDevice: isMaster)
        
        let userConfiguration = try UserConfiguration(
            publicSigningKey: privateSigningKey.publicKey.rawRepresentation,
            devices: [device],
            privateSigningKey: privateSigningKey)
        
        return CryptographicBundle(
            deviceKeys: deviceKeys,
            deviceConfiguration: device,
            userConfiguration: userConfiguration)
        
    }
    
    private func generateDatabasaeEncryptionKey() -> Data {
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
    /// - Returns: A `CryptoSession` object representing the created session.
    /// - Throws: An error of type `SessionErrors` if the session creation fails due to various reasons.
    public func createSession(
        secretName: String,
        appPassword: String,
        createInitialTransport: @Sendable @escaping () async throws -> Void
    ) async throws -> CryptoSession {
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
            databaseEncryptionKey: generateDatabasaeEncryptionKey(),
            sessionContextId: .random(in: 1 ..< .max),
            lastUserConfiguration: bundle.userConfiguration,
            registrationState: .unregistered)
        await setSessionContext(sessionContext)

        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
        }
        
        // Retrieve salt and derive symmetric key
        let saltData = try await cache.findLocalDeviceSalt(keyData: passwordData)
        
        let appSymmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
        
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
            
            //SHOULD NEVER HAPPEN
            throw SessionErrors.unknownError
        } catch let sessionError as SessionErrors {

            switch sessionError {
            case .userExists:
                throw sessionError
                
            case .userNotFound:
                // UserConfiguration does not contain Private keys/info... so it should be safe to store publicly.
                try! await transportDelegate?.publishUserConfiguration(bundle.userConfiguration, updateKeyBundle: false)
                
                sessionContext.registrationState = .registered
                await setSessionContext(sessionContext)
                
                
                let encodedData = try BSONEncoder().encodeData(sessionContext)
                guard let encryptedConfig = try! crypto.encrypt(data: encodedData, symmetricKey: appSymmetricKey) else {
                    throw SessionErrors.sessionEncryptionError
                }
                
                // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
                try! await cache.createLocalSessionContext(encryptedConfig)
                
                
                //Create Communication Model for personal messages
                await self.logger.log(level: .debug, message: "Creating Communication Model")
                
                let communicationModel = try await taskProcessor.jobProcessor.createCommunicationModel(
                    recipients: [secretName],
                    communicationType: .personalMessage,
                    metadata: [:],
                    symmetricKey: databaseEncryptionKey)
                
                guard var props = await communicationModel.props(symmetricKey: databaseEncryptionKey) else {
                    throw CryptoSession.SessionErrors.propsError
                }
                
                props.sharedId = UUID()
                
                try! await communicationModel.updateProps(symmetricKey: databaseEncryptionKey, props: props)
                
                try! await cache.createCommunication(communicationModel)
                try! await receiverDelegate?.updatedCommunication(communicationModel, members: [secretName])
                await self.logger.log(level: .debug, message: "Created Communication Model")
                
            default:
                throw sessionError
            }
        } catch {
            await logger.log(level: .error, message: "Error Creating Session, \(error)")
        }
        return CryptoSession.shared
    }
    
    public nonisolated(unsafe) weak var linkDelegate: DeviceLinkingDelegate?
    
    // This call must be followed by start session.
    public func linkDevice(
        bundle: CryptographicBundle,
        password: String
    ) async throws -> CryptoSession {
        await setAppPassword(password)
        // Create keys, we feed the SDK Consumer Keys in order to generate a QRCode for device linking
        let data = try BSONEncoder().encodeData(bundle.deviceConfiguration)
        if let credentials = await linkDelegate?.generatedDeviceCryptographic(data, password: password) {
            await setAppPassword(credentials.password)
            // Create a Session Identity
            let sessionUser = SessionUser(
                secretName: credentials.secretName,
                deviceId: bundle.deviceKeys.deviceId,
                deviceKeys: bundle.deviceKeys,
                metadata: .init()
            )
            
            //Used as the name suggestion to encrypt the local db models, this is their SymmetricKey
            let databaseEncryptionKey = generateDatabasaeEncryptionKey()
            
            let userConfiguration = try await createNewUser(
                configuration: bundle.userConfiguration,
                privateSigningKeyData: bundle.deviceKeys.privateSigningKey,
                devices: credentials.devices)
            
            var sessionContext = SessionContext(
                sessionUser: sessionUser,
                databaseEncryptionKey: databaseEncryptionKey,
                sessionContextId: .random(in: 1 ..< .max),
                lastUserConfiguration: userConfiguration,
                registrationState: .unregistered)
            await setSessionContext(sessionContext)
            
            guard let cache else {
                throw SessionErrors.databaseNotInitialized
            }
            
            try? await cache.deleteLocalSessionContext()
            try? await cache.deleteLocalDeviceSalt()
            
            guard let passwordData = await credentials.password.data(using: .utf8) else {
                throw SessionErrors.appPasswordError
            }
            
            // Retrieve salt and derive symmetric key
            let saltData = try await cache.findLocalDeviceSalt(keyData: passwordData)
            
            let symmetricKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData)
            
            sessionContext.registrationState = .registered
            await setSessionContext(sessionContext)
            
            let encodedData = try BSONEncoder().encode(sessionContext).makeData()
            guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
                throw SessionErrors.sessionEncryptionError
            }
            
            // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
            try await cache.createLocalSessionContext(encryptedConfig)
            
            //Create Communication Model for personal messages
            await self.logger.log(level: .debug, message: "Creating Communication Model")
            
            let communicationModel = try await taskProcessor.jobProcessor.createCommunicationModel(
                recipients: [credentials.secretName],
                communicationType: .personalMessage,
                metadata: [:],
                symmetricKey: symmetricKey)
            
            guard var props = await communicationModel.props(symmetricKey: symmetricKey) else {
                throw CryptoSession.SessionErrors.propsError
            }
            
            props.sharedId = UUID()
            
            try await communicationModel.updateProps(symmetricKey: symmetricKey, props: props)
            
            try await cache.createCommunication(communicationModel)
            try await receiverDelegate?.updatedCommunication(communicationModel, members: [credentials.secretName])
            await self.logger.log(level: .debug, message: "Created Communication Model")
            return try await startSession(appPassword: credentials.password)
        } else {
            throw SessionErrors.registrationError
        }
    }
    
    public func updateUserConfiguration(_ devices: [UserDeviceConfiguration]) async throws {
        guard let data = try await cache?.findLocalSessionContext() else { return }
        
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }
        
        // Decode the session context from the decrypted data
        var sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
        
        let userConfiguration = try await createNewUser(
            configuration: sessionContext.lastUserConfiguration,
            privateSigningKeyData: sessionContext.sessionUser.deviceKeys.privateSigningKey,
            devices: devices)
        sessionContext.lastUserConfiguration = userConfiguration
        await setSessionContext(sessionContext)
        
        let encodedData = try BSONEncoder().encode(sessionContext).makeData()
        guard let encryptedConfig = try await crypto.encrypt(data: encodedData, symmetricKey: getDatabaseSymmetricKey()) else {
            throw CryptoSession.SessionErrors.sessionEncryptionError
        }
        
        try await cache?.updateLocalSessionContext(encryptedConfig)
    }
    
    public func createNewUser(configuration: UserConfiguration, privateSigningKeyData: Data, devices: [UserDeviceConfiguration]) async throws -> UserConfiguration {
        let privateSigningKey = try Curve25519SigningPrivateKey(rawRepresentation: privateSigningKeyData)
        guard configuration.publicSigningKey == privateSigningKey.publicKey.rawRepresentation else {
            throw CryptoSession.SessionErrors.invalidSignature
        }
        
        // Verify the signature of the configuration
        guard try configuration.signed.verifySignature(publicKey: try Curve25519SigningPublicKey(rawRepresentation: configuration.publicSigningKey)) == true else { throw CryptoSession.SessionErrors.invalidSignature }
        // Decode the existing devices from the signed data
        var decoded = try BSONDecoder().decodeData([UserDeviceConfiguration].self, from: configuration.signed.data)
        
        
        // Append the new device configuration
        // Create a set of existing device IDs for quick lookup
        let existingDeviceIds = Set(decoded.map { $0.deviceId })
        
        // Filter out duplicates from the new devices
        let uniqueDevices = devices.filter { !existingDeviceIds.contains($0.deviceId) }
        
        // Append the unique devices to the decoded array
        decoded.append(contentsOf: uniqueDevices)
        
        // Return a new UserConfiguration with the updated devices
        return try UserConfiguration(
            publicSigningKey: configuration.publicSigningKey,
            devices: decoded,
            privateSigningKey: privateSigningKey)
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
        await setAppPassword(appPassword)
        // Ensure the identity store is initialized
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        // Retrieve the local device configuration
        let data = try await cache.findLocalSessionContext()
        
        // Convert the application password to Data
        guard let passwordData = appPassword.data(using: .utf8) else {
            throw SessionErrors.saltError
        }
        
        // Retrieve salt and derive symmetric key
        let saltData = try await cache.findLocalDeviceSalt(keyData: passwordData)
        
        // Derive the symmetric key from the password and salt
        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
        
        do {
            // Decrypt the configuration data
            guard let configurationData = try! crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
                throw SessionErrors.sessionDecryptionError
            }
            
            // Decode the session context from the decrypted data
            let sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
           
            await setSessionContext(sessionContext)
            return CryptoSession.shared
        } catch {
            throw error
        }
    }
    
    public func getDatabaseSymmetricKey() async throws -> SymmetricKey {
        guard let data = await sessionContext?.databaseEncryptionKey else { throw SessionErrors.sessionNotInitialized }
        return SymmetricKey(data: data)
    }
    
    public func getAppSymmetricKey() async throws -> SymmetricKey {
        guard let passwordData = await appPassword.data(using: .utf8) else {
            throw SessionErrors.invalidPassword
        }
        
        // Retrieve salt and derive symmetric key
        guard let saltData = try await cache?.findLocalDeviceSalt(keyData: passwordData) else { throw SessionErrors.saltError }
        
        return await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
    }
    
    public func verifyAppPassword(_ appPassword: String) async -> Bool {
        do {
            
            guard let passwordData = await appPassword.data(using: .utf8) else {
                throw SessionErrors.invalidPassword
            }
            
            guard let saltData = try await cache?.findLocalDeviceSalt(keyData: passwordData) else { throw SessionErrors.saltError }
            
            let appEncryptionKey = await crypto.deriveStrictSymmetricKey(
                data: passwordData,
                salt: saltData)
            guard let data = try await self.cache?.findLocalSessionContext() else { return false }
            let box = try AES.GCM.SealedBox(combined: data)
            _ = try AES.GCM.open(box, using: appEncryptionKey)
            return true
        } catch {
            return false
        }
    }
    
    public func changeAppPassword(_ newPassword: String) async throws {
        
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        
        let data = try await cache.findLocalSessionContext()
        guard let configurationData = try await crypto.decrypt(data: data, symmetricKey: getAppSymmetricKey()) else {
            throw SessionErrors.sessionDecryptionError
        }
        // Decode the session context from the decrypted data
        var sessionContext = try BSONDecoder().decode(SessionContext.self, from: Document(data: configurationData))
        try await cache.deleteLocalDeviceSalt()
        
        guard let passwordData = newPassword.data(using: .utf8) else {
            throw SessionErrors.appPasswordError
        }
        
        // Retrieve salt and derive symmetric key
        let saltData = try await cache.findLocalDeviceSalt(keyData: passwordData)
        
        let symmetricKey = await crypto.deriveStrictSymmetricKey(
            data: passwordData,
            salt: saltData)
        
        let encodedData = try BSONEncoder().encodeData(sessionContext)
        guard let encryptedConfig = try crypto.encrypt(data: encodedData, symmetricKey: symmetricKey) else {
            throw SessionErrors.sessionEncryptionError
        }
        
        // Create local device configuration. Only locally cached and save. Private keys/info are stored. Use with care...
        try await cache.updateLocalSessionContext(encryptedConfig)
        
        await setAppPassword(newPassword)
    }
    
    public func resumeJobQueue() async throws {
        guard let cache else {
            throw SessionErrors.databaseNotInitialized
        }
        try await taskProcessor.jobProcessor.loadJobs(
            nil,
            cache: cache,
            symmetricKey: getDatabaseSymmetricKey(),
            session: self)
    }
    
    public func shutdown() async {
        isViable = false
        cache = nil
        transportDelegate = nil
        receiverDelegate = nil
        linkDelegate = nil
        _sessionContext = nil
        _appPassword = ""
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
        var size: Int = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        
        return String(cString: model)
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
            
            // Mac Pro (2019 and later)
            "MacPro7,1": "Mac Pro (2019)",
            
            // Mac Studio (2022 and later)
            "Mac13,1": "Mac Studio (2022)",
            
            // Mac mini (2018 and later)
            "Macmini8,1": "Mac mini (2018)",
            "Macmini9,1": "Mac mini (M1, 2020)",
            "Mac14,4": "Mac mini (M2, 2022)"
        ]
        
        
        return deviceNames[modelIdentifier] ?? modelIdentifier
#else
        return "Unkown Device Model"
#endif
    }
}
