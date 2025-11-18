//
//  Contact.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-06-29.
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
import Foundation

/// A struct representing a contact in the messaging system.
///
/// This struct encapsulates the essential information about a contact including their unique identifier,
/// secret name for identification, user configuration settings, and additional metadata. It conforms to
/// `Sendable`, `Codable`, and `Equatable` protocols to ensure thread safety, serialization capabilities,
/// and comparison operations.
///
/// ## Usage
/// ```swift
/// let contact = Contact(
///     id: UUID(),
///     secretName: "alice_secure",
///     configuration: UserConfiguration(),
///     metadata: ["lastSeen": Date()]
/// )
/// ```
///
/// ## Properties
/// - `id`: The unique identifier for the contact, used for database operations and message routing
/// - `secretName`: The secret name associated with the contact, used for secure identification
/// - `configuration`: The user configuration settings that define the contact's behavior and preferences
/// - `metadata`: Additional metadata stored as keyed Foundation Data for extensibility
public struct Contact: Sendable, Codable, Equatable, Hashable {
    /// The unique identifier for the contact.
    /// This UUID is used throughout the system for database operations, message routing, and contact identification.
    public let id: UUID

    /// The secret name associated with the contact, used for identification.
    /// This name is used in secure communications and should be unique within the user's contact list.
    public let secretName: String

    /// The user configuration settings for the contact.
    /// Contains preferences, security settings, and other configuration options that affect how
    /// the system interacts with this contact.
    public var configuration: UserConfiguration

    /// Additional metadata associated with the contact.
    /// Stored as keyed Foundation Data to allow for flexible storage of contact-specific information
    /// such as last seen timestamps, relationship status, or custom fields.
    public var metadata: [String: Data]

    /// Initializes a new instance of `Contact`.
    ///
    /// Creates a contact with the specified properties. All parameters are required to ensure
    /// data integrity and proper contact identification.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the contact. Should be a valid UUID.
    ///   - secretName: The secret name associated with the contact. Used for secure identification.
    ///   - configuration: The user configuration settings for the contact. Defines behavior and preferences.
    ///   - metadata: Additional metadata associated with the contact. Can be empty or contain custom data.
    public init(id: UUID, secretName: String, configuration: UserConfiguration, metadata: [String: Data]) {
        self.id = id
        self.secretName = secretName
        self.configuration = configuration
        self.metadata = metadata
    }
    
    public static func == (lhs: Contact, rhs: Contact) -> Bool {
          lhs.id == rhs.id
      }
      
      public func hash(into hasher: inout Hasher) {
          hasher.combine(id)
      }
}
