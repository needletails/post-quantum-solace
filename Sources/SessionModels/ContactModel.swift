//
//  ContactModel.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-18.
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

import DoubleRatchetKit
import Foundation

/// A class representing a secure model for a contact in the messaging system.
///
/// This class provides encrypted storage for contact information, ensuring that sensitive contact data
/// is protected at rest. It implements the `SecureModelProtocol` to provide a consistent interface
/// for secure data models throughout the system.
///
/// ## Security Features
/// - All contact data is encrypted using symmetric key encryption
/// - Thread-safe operations with proper locking mechanisms
/// - Secure serialization and deserialization of contact properties
///
/// ## Usage
/// ```swift
/// let contactModel = try ContactModel(
///     id: UUID(),
///     props: ContactModel.UnwrappedProps(
///         secretName: "bob_secure",
///         configuration: UserConfiguration(),
///         metadata: ["trustLevel": "high"]
///     ),
///     symmetricKey: symmetricKey
/// )
/// ```
///
/// ## Thread Safety
/// This class uses `@unchecked Sendable` because it manages its own thread safety through
/// the `NIOLock` mechanism. All operations that modify the encrypted data are properly synchronized.
public final class ContactModel: SecureModelProtocol, Codable, @unchecked Sendable {
    /// The unique identifier for the contact model.
    /// This UUID serves as the primary key for the contact and is used for database operations.
    public let id: UUID
    
    /// The encrypted data associated with the contact model.
    /// Contains the serialized and encrypted contact properties. This data is opaque and
    /// requires the correct symmetric key for decryption.
    public var data: Data
    
    /// A lock for synchronizing access to the model's properties.
    /// Ensures thread-safe operations when reading or writing the encrypted data.
    private let lock = NSLock()
    
    /// An instance of the cryptographic utility used for encryption and decryption.
    /// Provides the encryption/decryption capabilities for securing contact data.
    private let crypto = NeedleTailCrypto()
    
    /// Coding keys for serialization and deserialization.
    /// Uses abbreviated keys to minimize storage overhead while maintaining readability.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// Asynchronously retrieves the decrypted properties of the contact model, if available.
    ///
    /// This method attempts to decrypt the stored data using the provided symmetric key.
    /// If decryption fails, it returns `nil` instead of throwing an error, making it safe
    /// for scenarios where the key might be incorrect or the data corrupted.
    ///
    /// - Parameter symmetricKey: The symmetric key used for decryption. Must be the same key
    ///   that was used for encryption.
    /// - Returns: The decrypted properties as `UnwrappedProps`, or `nil` if decryption fails.
    ///   The returned object contains all the contact's properties in a readable format.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }
    
    /// A struct representing the unwrapped properties of a contact model.
    ///
    /// This struct contains the decrypted and deserialized contact data. It's used internally
    /// for working with contact properties in a readable format before re-encryption.
    ///
    /// ## Properties
    /// - `secretName`: The contact's secret name for identification
    /// - `configuration`: The contact's user configuration settings
    /// - `metadata`: Additional metadata stored as keyed Foundation Data
    public struct UnwrappedProps: Codable, Sendable {
        /// Coding keys for serialization and deserialization.
        /// Uses abbreviated keys to minimize storage overhead.
        private enum CodingKeys: String, CodingKey, Sendable {
            case secretName = "a"
            case configuration = "b"
            case metadata = "c"
        }
        
        /// The secret name associated with the contact.
        /// Used for secure identification in communications and database operations.
        public let secretName: String
        
        /// The user configuration settings for the contact.
        /// Contains preferences, security settings, and other configuration options.
        public var configuration: UserConfiguration
        
        /// Additional metadata associated with the contact.
        /// Flexible storage for contact-specific information using Foundation Data format.
        public var metadata: [String: Data]
        
        /// Initializes a new instance of `UnwrappedProps`.
        ///
        /// Creates a new unwrapped properties object with the specified contact information.
        ///
        /// - Parameters:
        ///   - secretName: The secret name for the contact
        ///   - configuration: The user configuration settings
        ///   - metadata: Additional metadata as keyed Foundation Data
        public init(
            secretName: String,
            configuration: UserConfiguration,
            metadata: [String: Data]
        ) {
            self.secretName = secretName
            self.configuration = configuration
            self.metadata = metadata
        }
    }
    
    /// Initializes a new instance of `ContactModel` with encrypted properties.
    ///
    /// Creates a new contact model by encrypting the provided properties using the specified
    /// symmetric key. The properties are serialized to Foundation Data before encryption.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the contact model. Should be a valid UUID.
    ///   - props: The unwrapped properties to be encrypted. Contains all contact information.
    ///   - symmetricKey: The symmetric key used for encryption. Must be kept secure.
    /// - Throws: `CryptoError.encryptionFailed` if the encryption process fails.
    public init(
        id: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        let data = try BinaryEncoder().encode(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    /// Initializes a new instance of `ContactModel` with existing encrypted data.
    ///
    /// Creates a contact model from pre-existing encrypted data. This is typically used
    /// when loading contact data from persistent storage.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the contact model. Should match the original contact ID.
    ///   - data: The encrypted data associated with the contact model. Must be valid encrypted data.
    public init(
        id: UUID,
        data: Data
    ) {
        self.id = id
        self.data = data
    }
    
    /// Asynchronously decrypts the properties of the contact model.
    ///
    /// Decrypts the stored data using the provided symmetric key and deserializes it into
    /// an `UnwrappedProps` object. This method is thread-safe and handles the decryption
    /// process internally.
    ///
    /// - Parameter symmetricKey: The symmetric key used for decryption. Must be the same key
    ///   that was used for encryption.
    /// - Returns: The decrypted properties as `UnwrappedProps` containing all contact information.
    /// - Throws: `CryptoError.decryptionFailed` if decryption fails, or a decoding error if
    ///   the decrypted data cannot be deserialized.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        try lock.withLock { [weak self] in
            guard let self else { throw CryptoError.encryptionFailed }
            guard let decrypted = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
                throw CryptoError.decryptionFailed
            }
            return try BinaryDecoder().decode(UnwrappedProps.self, from: decrypted)
        }
    }
    
    /// Asynchronously updates the properties of the contact model.
    ///
    /// Updates the contact's properties by encrypting the new data and replacing the existing
    /// encrypted data. This operation is atomic and thread-safe.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption. Must be kept secure.
    ///   - props: The new unwrapped properties to be set. Replaces all existing properties.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: `CryptoError.encryptionFailed` if encryption fails, or other errors from
    ///   the serialization process.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        let data = try BinaryEncoder().encode(props)
        do {
            try lock.withLock { [weak self] in
                guard let self else { throw CryptoError.encryptionFailed }
                guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
                    throw CryptoError.encryptionFailed
                }
                self.data = encryptedData
            }
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            throw error
        }
    }
    
    /// Asynchronously updates the metadata of the contact model using the provided symmetric key.
    ///
    /// Updates a specific metadata key with new data while preserving all other contact properties.
    /// This method is useful for updating individual pieces of metadata without affecting
    /// the rest of the contact information.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption and decryption.
    ///   - metadata: The new metadata to be set. Will replace the existing metadata for the specified key.
    ///   - key: The key under which the metadata will be stored. Must be a valid string.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: Various errors if decryption, encryption, or serialization fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    /// Asynchronously updates the metadata of the contact model using the provided symmetric key.
    ///
    /// Merges new metadata with existing metadata, updating only the keys that are present
    /// in the new metadata while preserving all other existing metadata.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption and decryption.
    ///   - metadata: The new metadata to be merged with the existing metadata. Only keys present
    ///     in this metadata will be updated.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: Various errors if decryption, encryption, or serialization fails.
//    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data) async throws -> UnwrappedProps? {
//        var props = try await decryptProps(symmetricKey: symmetricKey)
//        
//        var newMetadata = props.metadata
//        for key in metadata.keys {
//            if let value = metadata[key] {
//                newMetadata[key] = value
//            }
//        }
//        props.metadata = newMetadata
//        return try await updateProps(symmetricKey: symmetricKey, props: props)
//    }
    
    /// Creates a decrypted model of the specified type from the contact properties.
    ///
    /// This method creates a decrypted `Contact` object from the encrypted contact model.
    /// It's useful for converting the secure model back to a regular contact object for
    /// use in the application layer.
    ///
    /// - Parameters:
    ///   - of: The type of the model to create, which must conform to `Sendable` and `Codable`.
    ///     Currently supports `Contact` type.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type populated with the decrypted properties.
    /// - Throws: `Errors.propsError` if decryption fails, or other errors from the conversion process.
    public func makeDecryptedModel<T: Sendable & Codable>(of _: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw Errors.propsError
        }
        return Contact(
            id: id,
            secretName: props.secretName,
            configuration: props.configuration,
            metadata: props.metadata
        ) as! T
    }
    
    /// Asynchronously updates the contact's metadata.
    ///
    /// Updates the contact's metadata with new information, merging it with existing metadata
    /// if present. This method specifically handles `ContactMetadata` objects and provides
    /// intelligent merging of properties.
    ///
    /// - Parameters:
    ///   - metadata: The new contact metadata to be updated. Only non-nil properties will be updated.
    ///   - symmetricKey: The symmetric key used for encryption and decryption.
    /// - Returns: The updated decrypted properties as `UnwrappedProps` for verification.
    /// - Throws: `Errors.propsError` if decryption fails, or other errors from the update process.
    public func updateContact(_ metadata: ContactMetadata, symmetricKey: SymmetricKey) async throws -> UnwrappedProps? {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw Errors.propsError
        }
        
        var contactMetadata: ContactMetadata
        if let contactData = props.metadata["contactMetadata"], !contactData.isEmpty {
            // Decode the existing metadata
            contactMetadata = try BinaryDecoder().decode(ContactMetadata.self, from: contactData)
            // Update properties only if they are not nil
            if let status = metadata.status {
                contactMetadata.status = status
            }
            if let nickname = metadata.nickname {
                contactMetadata.nickname = nickname
            }
            if let firstName = metadata.firstName {
                contactMetadata.firstName = firstName
            }
            if let lastName = metadata.lastName {
                contactMetadata.lastName = lastName
            }
            if let email = metadata.email {
                contactMetadata.email = email
            }
            if let image = metadata.image {
                contactMetadata.image = image
            }
        } else {
            contactMetadata = ContactMetadata(
                status: metadata.status,
                nickname: metadata.nickname,
                firstName: metadata.firstName,
                lastName: metadata.lastName,
                email: metadata.email,
                image: metadata.image
            )
        }
        
        let metadata = try BinaryEncoder().encode(contactMetadata)
        // Encode the updated metadata
        return try await updatePropsMetadata(
            symmetricKey: symmetricKey,
            metadata: metadata,
            with: "contactMetadata"
        )
    }
    
    /// An enumeration representing possible errors that can occur within the `ContactModel`.
    ///
    /// Defines the specific error types that can be thrown by the contact model operations.
    private enum Errors: Error, LocalizedError {
        /// Indicates an error occurred while retrieving or updating properties.
        /// This typically happens when decryption fails or properties cannot be accessed.
        case propsError
        
        public var errorDescription: String? {
            "Error occurred while retrieving or updating properties"
        }
        
        public var failureReason: String? {
            "Decryption failed or properties cannot be accessed"
        }
    }
}
