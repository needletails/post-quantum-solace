//
//  SessionContext.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-14.
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
//
import Foundation

/// A struct representing the context of a user session, including user information,
/// encryption keys, and configuration state.
///
/// This struct serves as the central container for all session-related data,
/// providing a secure and organized way to manage user sessions in the post-quantum
/// cryptography system. It implements `Codable` for serialization and `Sendable`
/// for thread safety.
///
/// - Note: The coding keys use single-letter identifiers for security through obscurity,
///         making it harder for attackers to understand the serialized data structure.
public struct SessionContext: Codable & Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    ///
    /// Uses single-letter keys to obfuscate the data structure and reduce payload size
    /// while maintaining security through obscurity principles.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case sessionUser = "a" // Key for the session user
        case databaseEncryptionKey = "b" // Key for the database encryption key
        case sessionContextId = "c" // Key for the session context identity
        case activeUserConfiguration = "d" // Key for the last user configuration
        case registrationState = "e" // Key for the registration state
    }

    /// The session user associated with this context.
    ///
    /// Contains user-specific information and credentials for the current session.
    public var sessionUser: SessionUser

    /// Data representing the encryption key used for securing the database.
    ///
    /// This key is used to encrypt and decrypt sensitive data stored in the local database.
    /// The key should be securely generated and stored.
    public let databaseEncryptionKey: Data

    /// Unique identifier for the device associated with the session.
    ///
    /// This identifier distinguishes between different devices that may be associated
    /// with the same user account.
    public let sessionContextId: Int

    /// The current active user configuration associated with the session.
    ///
    /// Contains the user's current cryptographic identity, including signed device configurations,
    /// one-time public keys, and signing keys. This configuration is actively used for all
    /// cryptographic operations and is updated throughout the session lifecycle as keys are
    /// rotated, devices are added, or one-time keys are refreshed.
    public var activeUserConfiguration: UserConfiguration

    /// The current registration state of the user.
    ///
    /// Indicates whether the user has completed the registration process or is still
    /// in an unregistered state.
    public var registrationState: RegistrationState

    /// Initializes a new instance of `SessionContext`.
    ///
    /// - Parameters:
    ///   - sessionUser: The session user associated with this context.
    ///   - databaseEncryptionKey data: The encryption key used for securing the database.
    ///   - sessionContextId: Unique identifier for the device associated with the session.
    ///   - activeUserConfiguration: The last user configuration associated with the session.
    ///   - registrationState: The current registration state of the user.
    ///
    /// - Important: The `databaseEncryptionKey` should be securely generated and
    ///              should not be shared or exposed in logs or error messages.
    public init(
        sessionUser: SessionUser,
        databaseEncryptionKey data: Data,
        sessionContextId: Int,
        activeUserConfiguration: UserConfiguration,
        registrationState: RegistrationState
    ) {
        self.sessionUser = sessionUser
        databaseEncryptionKey = data
        self.sessionContextId = sessionContextId
        self.activeUserConfiguration = activeUserConfiguration
        self.registrationState = registrationState
    }

    /// Updates the session user with a new value.
    ///
    /// This method allows for updating the session user information, which may be
    /// necessary when user credentials change or when switching between different
    /// user accounts.
    ///
    /// - Parameter newSessionUser: The new session user to be set.
    ///
    /// - Note: This method is marked as `mutating` since it modifies the struct's
    ///          `sessionUser` property.
    public mutating func updateSessionUser(_ newSessionUser: SessionUser) {
        sessionUser = newSessionUser
    }
    
    public static func == (lhs: SessionContext, rhs: SessionContext) -> Bool {
        lhs.sessionUser.deviceId == rhs.sessionUser.deviceId
    }
}

/// An enumeration representing the registration state of a user.
///
/// This enum tracks whether a user has completed the registration process,
/// which is essential for determining what operations are available to the user.
public enum RegistrationState: Codable, Sendable {
    /// The user has completed the registration process and has full access.
    case registered

    /// The user has not completed the registration process and has limited access.
    case unregistered
}

/// A struct representing information for linking devices, including a secret name,
/// device configurations, and a password.
///
/// This struct encapsulates all the necessary information required to establish
/// a secure connection between multiple devices for the same user account.
/// It implements `Sendable` to ensure thread safety when passed between
/// concurrent contexts.
public struct LinkDeviceInfo: Sendable {
    /// The name of the secret associated with the device link.
    ///
    /// This identifier is used to uniquely identify the device linking session
    /// and should be kept secure.
    public let secretName: String

    /// An array of device configurations associated with the user.
    ///
    /// Contains configuration information for all devices that are or will be
    /// linked to this user account.
    public let devices: [UserDeviceConfiguration]

    /// The password used for securing the device link.
    ///
    /// This password is used to authenticate and secure the device linking process.
    /// It should be strong and kept confidential.
    public let password: String

    /// Initializes a new instance of `LinkDeviceInfo`.
    ///
    /// - Parameters:
    ///   - secretName: The name of the secret associated with the device link.
    ///   - devices: An array of device configurations associated with the user.
    ///   - password: The password used for securing the device link.
    ///
    /// - Important: The `password` should be strong and securely managed.
    ///              Avoid storing it in plain text or logging it.
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
///
/// This protocol provides a way to handle device linking operations asynchronously,
/// allowing for secure cryptographic operations during the device linking process.
/// It implements `Sendable` to ensure thread safety in concurrent environments.
public protocol DeviceLinkingDelegate: AnyObject, Sendable {
    /// Asynchronously generates cryptographic data for a device.
    ///
    /// This method is responsible for creating the necessary cryptographic information
    /// required to securely link a new device to an existing user account.
    ///
    /// - Parameters:
    ///   - data: The input data to be used for generating cryptographic information.
    ///           This typically includes device-specific information and user credentials.
    ///   - password: The password associated with the device linking process.
    ///               This should be the same password used in the `LinkDeviceInfo`.
    ///
    /// - Returns: An optional `LinkDeviceInfo` containing the generated information
    ///            if the cryptographic generation was successful, or `nil` if the
    ///            operation failed.
    ///
    /// - Note: This method is asynchronous to allow for potentially time-consuming
    ///          cryptographic operations without blocking the calling thread.
    func generateDeviceCryptographic(_ data: Data, password: String) async -> LinkDeviceInfo?
}
