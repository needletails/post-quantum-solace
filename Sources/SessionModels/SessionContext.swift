//
//  SessionContext.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation

/// A struct representing the context of a user session, including user information,
/// encryption keys, and configuration state.
public struct SessionContext: Codable & Sendable {
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case sessionUser = "a"                // Key for the session user
        case databaseEncryptionKey = "b"      // Key for the database encryption key
        case sessionContextId = "c"           // Key for the session context identity
        case lastUserConfiguration = "d"       // Key for the last user configuration
        case registrationState = "e"           // Key for the registration state
    }
    
    /// The session user associated with this context.
    public var sessionUser: SessionUser
    
    /// Data representing the encryption key used for securing the database.
    public let databaseEncryptionKey: Data
    
    /// Unique identifier for the device associated with the session.
    public let sessionContextId: Int
    
    /// The last user configuration associated with the session.
    public var lastUserConfiguration: UserConfiguration
    
    /// The current registration state of the user.
    public var registrationState: RegistrationState
    
    /// Initializes a new instance of `SessionContext`.
    ///
    /// - Parameters:
    ///   - sessionUser: The session user associated with this context.
    ///   - databaseEncryptionKey: The encryption key used for securing the database.
    ///   - sessionContextId: Unique identifier for the device associated with the session.
    ///   - lastUserConfiguration: The last user configuration associated with the session.
    ///   - registrationState: The current registration state of the user.
    public init(
        sessionUser: SessionUser,
        databaseEncryptionKey: Data,
        sessionContextId: Int,
        lastUserConfiguration: UserConfiguration,
        registrationState: RegistrationState
    ) {
        self.sessionUser = sessionUser
        self.databaseEncryptionKey = databaseEncryptionKey
        self.sessionContextId = sessionContextId
        self.lastUserConfiguration = lastUserConfiguration
        self.registrationState = registrationState
    }
    
    /// Updates the session user with a new value.
    ///
    /// - Parameter newSessionUser: The new session user to be set.
    public mutating func updateSessionUser(_ newSessionUser: SessionUser) {
        self.sessionUser = newSessionUser
    }
}

/// An enumeration representing the registration state of a user.
public enum RegistrationState: Codable, Sendable {
    case registered, unregistered
}

/// A struct representing information for linking devices, including a secret name,
/// device configurations, and a password.
public struct LinkDeviceInfo: Sendable {
    
    /// The name of the secret associated with the device link.
    public let secretName: String
    
    /// An array of device configurations associated with the user.
    public let devices: [UserDeviceConfiguration]
    
    /// The password used for securing the device link.
    public let password: String
    
    /// Initializes a new instance of `LinkDeviceInfo`.
    ///
    /// - Parameters:
    ///   - secretName: The name of the secret associated with the device link.
    ///   - devices: An array of device configurations associated with the user.
    ///   - password: The password used for securing the device link.
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

/// A protocol defining a delegate for device linking operations.
public protocol DeviceLinkingDelegate: AnyObject, Sendable {
    
    /// Asynchronously generates cryptographic data for a device.
    ///
    /// - Parameters:
    ///   - data: The data to be used for generating cryptographic information.
    ///   - password: The password associated with the device.
    /// - Returns: An optional `LinkDeviceInfo` containing the generated information.
    func generatedDeviceCryptographic(_ data: Data, password: String) async -> LinkDeviceInfo?
}
