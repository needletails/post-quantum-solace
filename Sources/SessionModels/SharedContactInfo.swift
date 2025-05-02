//
//  SharedContactInfo.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//
import Foundation
import struct BSON.Document

/// A struct representing shared contact information, including a secret name,
/// associated metadata, and an optional shared communication identifier.
public struct SharedContactInfo: Codable, Sendable {
    
    /// The name of the secret associated with the shared contact.
    public let secretName: String
    
    /// The metadata associated with the shared contact, represented as a `Document`.
    public let metadata: Document
    
    /// An optional unique identifier for shared communication related to the contact.
    public let sharedCommunicationId: UUID?
    
    /// Initializes a new instance of `SharedContactInfo`.
    ///
    /// - Parameters:
    ///   - secretName: The name of the secret associated with the shared contact.
    ///   - metadata: The metadata associated with the shared contact.
    ///   - sharedCommunicationId: An optional unique identifier for shared communication
    ///     related to the contact.
    public init(secretName: String, metadata: Document, sharedCommunicationId: UUID?) {
        self.secretName = secretName
        self.metadata = metadata
        self.sharedCommunicationId = sharedCommunicationId
    }
}
