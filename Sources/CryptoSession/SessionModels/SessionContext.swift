//
//  SessionContext.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation

/// A struct representing the context of a user session, including user information, encryption keys, and configuration state.
public struct SessionContext: Codable & Sendable {
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case sessionUser = "a"                // Key for the session user
        case databaseEncryptionKey = "b"  // Key for the database encryption key
        case sessionContextId = "c"      // Key for the session context identity
        case lastUserConfiguration = "d"    // Key for the last user configuration
        case registrationState = "e"      // Key for the registration state
    }
    
    /// The session user associated with this context.
    var sessionUser: SessionUser
    /// Data representing the encryption key used for securing the database.
    let databaseEncryptionKey: Data
    /// Unique identifier for the device associated with the session.
    let sessionContextId: Int
    /// The last user configuration associated with the session.
    var lastUserConfiguration: UserConfiguration
    /// The current registration state of the user.
    var registrationState: RegistrationState
}
