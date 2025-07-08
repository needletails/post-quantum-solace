//
//  Contact.swift
//  post-quantum-solace
//
//  Created by Cole M on 6/29/25.
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
import struct BSON.Document
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
/// - `metadata`: Additional metadata stored as a BSON document for extensibility
public struct Contact: Sendable, Codable, Equatable {
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
    /// Stored as a BSON document to allow for flexible storage of contact-specific information
    /// such as last seen timestamps, relationship status, or custom fields.
    public var metadata: Document

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
    public init(id: UUID, secretName: String, configuration: UserConfiguration, metadata: Document) {
        self.id = id
        self.secretName = secretName
        self.configuration = configuration
        self.metadata = metadata
    }
}
