//
//  SharedContactInfo.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/19/25.
//
import struct BSON.Document
import Foundation

/// A structure representing shared contact information for secure communication.
///
/// This struct encapsulates essential contact data that can be shared between users
/// in a secure messaging system. It conforms to the `Codable` and `Sendable` protocols,
/// allowing it to be safely serialized for network transmission and used across
/// concurrent tasks.
///
/// ## Properties
/// - `secretName`: The secret name associated with the shared contact, used for
///   privacy-preserving identification.
/// - `metadata`: Additional metadata associated with the shared contact, represented
///   as a BSON `Document` for flexible data storage.
/// - `sharedCommunicationId`: An optional unique identifier for shared communication
///   channels related to the contact.
///
/// ## Usage
/// This struct is typically used when sharing contact information between users
/// in a secure messaging application, allowing for the exchange of contact details
/// while maintaining privacy through the use of secret names and optional
/// communication identifiers.
///
/// ## Important
/// The `secretName` should be treated as sensitive information and should not be
/// logged or exposed in error messages. The `metadata` field provides flexibility
/// for storing additional contact-related information without requiring struct
/// modifications.
public struct SharedContactInfo: Codable, Sendable {
    /// The secret name associated with the shared contact.
    ///
    /// This identifier is used for privacy-preserving contact identification
    /// in the secure messaging system. It should be treated as sensitive
    /// information and not exposed in logs or error messages.
    public let secretName: String

    /// The metadata associated with the shared contact, represented as a BSON `Document`.
    ///
    /// This field provides flexible storage for additional contact-related information
    /// such as profile data, preferences, or other metadata that may be associated
    /// with the contact. The BSON format allows for efficient serialization and
    /// flexible schema evolution.
    public let metadata: Document

    /// An optional unique identifier for shared communication related to the contact.
    ///
    /// When present, this identifier can be used to establish or reference
    /// shared communication channels between users. This is particularly useful
    /// for group conversations or persistent communication sessions.
    public let sharedCommunicationId: UUID?

    /// Initializes a new instance of `SharedContactInfo`.
    ///
    /// - Parameters:
    ///   - secretName: The secret name associated with the shared contact. This
    ///     should be a unique, privacy-preserving identifier for the contact.
    ///   - metadata: The metadata associated with the shared contact. This can
    ///     contain any additional information about the contact in BSON format.
    ///   - sharedCommunicationId: An optional unique identifier for shared
    ///     communication channels related to the contact. Use `nil` if no
    ///     shared communication is associated with this contact.
    public init(secretName: String, metadata: Document, sharedCommunicationId: UUID?) {
        self.secretName = secretName
        self.metadata = metadata
        self.sharedCommunicationId = sharedCommunicationId
    }
}
