//
//  BaseCommunication.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-04-18.
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

import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto

/// A protocol that defines the requirements for communication models in the messaging system.
///
/// This protocol ensures that all communication models can be serialized for storage/transmission
/// and safely shared across different threads in concurrent environments.
///
/// - Note: All implementations must provide access to their underlying `BaseCommunication` object
///   to enable encryption/decryption operations.
public protocol CommunicationProtocol: Codable & Sendable {
    /// The base communication object that handles encryption and decryption of the model's data.
    ///
    /// This property provides access to the underlying encrypted storage and cryptographic operations
    /// for the communication model.
    var base: BaseCommunication { get }
}

/// A struct representing a communication model in a messaging system.
///
/// This struct encapsulates all the metadata and state information for a communication channel,
/// including participants, permissions, and message tracking. It conforms to `Sendable` and `Codable`
/// for thread safety and serialization capabilities.
///
/// - Note: This struct is designed to be immutable after creation to ensure thread safety.
public struct Communication: Sendable & Codable {
    /// The unique identifier for this communication channel.
    public let id: UUID

    /// An optional shared identifier that can be used to group related communications.
    ///
    /// This is typically used when multiple communication channels are part of the same
    /// logical conversation or workspace.
    public let sharedId: UUID?

    /// The total number of messages that have been sent in this communication.
    ///
    /// This counter is used for message ordering and synchronization purposes.
    public var messageCount: Int

    /// The identifier of the user who has administrative privileges for this communication.
    ///
    /// Administrators can typically modify channel settings, add/remove members, and manage permissions.
    public var administrator: String?

    /// A set of user identifiers who have operator privileges in this communication.
    ///
    /// Operators have elevated permissions compared to regular members but less than administrators.
    public var operators: Set<String>?

    /// The set of user identifiers who are active members of this communication.
    ///
    /// Members can send and receive messages in this communication channel.
    public var members: Set<String>

    /// The set of user identifiers who have been blocked from participating in this communication.
    ///
    /// Blocked members cannot send messages or view communication content.
    public let blockedMembers: Set<String>

    /// Additional metadata associated with this communication.
    ///
    /// This can include custom properties, settings, or other contextual information
    /// specific to the communication channel.
    public var metadata: Document

    /// The type of message recipient this communication represents.
    ///
    /// This determines how messages are routed and who can participate in the communication.
    public var communicationType: MessageRecipient
}

/// A base class for communication models that provides encryption and decryption capabilities.
///
/// This class serves as the foundation for secure communication by encrypting all sensitive
/// communication data using symmetric key cryptography. It conforms to `Codable` for serialization
/// and uses `@unchecked Sendable` since the cryptographic operations are thread-safe.
///
/// - Important: All communication data is encrypted at rest and only decrypted when needed
///   for processing. This ensures that sensitive information remains protected even if
///   the storage medium is compromised.
///
/// - Note: This class is marked as `@unchecked Sendable` because the underlying cryptographic
///   operations are thread-safe, but the class itself doesn't automatically guarantee thread safety.
public final class BaseCommunication: Codable, @unchecked Sendable {
    /// The unique identifier for this communication.
    public let id: UUID

    /// The encrypted data containing all communication properties.
    ///
    /// This data is encrypted using the symmetric key provided during initialization
    /// and can only be decrypted with the same key.
    public var data: Data

    /// Coding keys for serialization, using obfuscated names for security.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id, data = "a"
    }

    /// Asynchronously retrieves the decrypted properties of the communication model.
    ///
    /// This method decrypts the stored data using the provided symmetric key and returns
    /// the unwrapped properties. If decryption fails, it returns `nil` instead of throwing
    /// an error to provide a more graceful failure mode.
    ///
    /// - Parameter symmetricKey: The symmetric key used for decryption. Must be the same
    ///   key that was used to encrypt the data originally.
    /// - Returns: The decrypted properties as `UnwrappedProps`, or `nil` if decryption fails.
    ///
    /// - Note: This method is designed to handle decryption failures gracefully by returning
    ///   `nil` rather than throwing an error, making it suitable for scenarios where
    ///   decryption might fail due to key mismatches or corrupted data.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    /// A struct representing the unwrapped properties of a communication model.
    ///
    /// This struct contains all the decrypted properties of a communication channel,
    /// including participant information, permissions, and metadata. It uses obfuscated
    /// coding keys to prevent easy identification of the stored data structure.
    ///
    /// - Note: The coding keys are obfuscated (using single letters) to make it harder
    ///   for attackers to understand the data structure even if they gain access to
    ///   the encrypted data.
    public struct UnwrappedProps: Codable & Sendable {
        /// Coding keys with obfuscated names for enhanced security.
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case sharedId = "a"
            case messageCount = "b"
            case administrator = "c"
            case members = "d"
            case operators = "e"
            case blockedMembers = "f"
            case metadata = "g"
            case communicationType = "h"
        }

        /// An optional shared identifier for grouping related communications.
        public var sharedId: UUID?

        /// The total number of messages in this communication.
        public var messageCount: Int

        /// The identifier of the administrator for this communication.
        public var administrator: String?

        /// The set of user identifiers with operator privileges.
        public var operators: Set<String>?

        /// The set of active member identifiers.
        public var members: Set<String>

        /// The set of blocked member identifiers.
        public let blockedMembers: Set<String>

        /// Additional metadata for the communication.
        public var metadata: Document

        /// The type of message recipient this communication represents.
        public var communicationType: MessageRecipient

        /// Initializes a new instance of `UnwrappedProps` with the specified values.
        ///
        /// - Parameters:
        ///   - sharedId: An optional shared identifier for grouping communications.
        ///   - messageCount: The initial message count for this communication.
        ///   - administrator: The identifier of the administrator, if any.
        ///   - operators: The set of operator identifiers, if any.
        ///   - members: The set of member identifiers. Must not be empty for a valid communication.
        ///   - metadata: Additional metadata for the communication.
        ///   - blockedMembers: The set of blocked member identifiers.
        ///   - communicationType: The type of message recipient this communication represents.
        ///
        /// - Note: The `members` parameter should typically contain at least one member
        ///   for the communication to be functional.
        public init(
            sharedId: UUID? = nil,
            messageCount: Int,
            administrator: String? = nil,
            operators: Set<String>? = nil,
            members: Set<String>,
            metadata: Document,
            blockedMembers: Set<String>,
            communicationType: MessageRecipient
        ) {
            self.sharedId = sharedId
            self.messageCount = messageCount
            self.administrator = administrator
            self.operators = operators
            self.members = members
            self.metadata = metadata
            self.blockedMembers = blockedMembers
            self.communicationType = communicationType
        }
    }

    /// Initializes a new instance of `BaseCommunication` with encrypted properties.
    ///
    /// This initializer creates a new communication object by encrypting the provided
    /// properties using the specified symmetric key. The encrypted data is stored
    /// and can only be decrypted using the same key.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the communication. This should be a UUID
    ///     that uniquely identifies this communication across the system.
    ///   - props: The unwrapped properties to be encrypted. These properties will
    ///     be serialized and encrypted before storage.
    ///   - symmetricKey: The symmetric key used for encryption. This key must be
    ///     securely managed and shared only with authorized parties who need to
    ///     decrypt the communication data.
    ///
    /// - Throws: `CryptoError.encryptionFailed` if the encryption process fails.
    ///
    /// - Note: The symmetric key should be derived from a secure key exchange
    ///   process and should be unique to this communication or a group of related
    ///   communications.
    public init(
        id: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }

    /// Initializes a new instance of `BaseCommunication` with existing encrypted data.
    ///
    /// This initializer is used when loading an existing communication from storage
    /// or when receiving encrypted communication data from another source. The data
    /// is stored as-is and will be decrypted when the `props(symmetricKey:)` method
    /// is called.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the communication.
    ///   - data: The encrypted data associated with the communication. This data
    ///     should have been encrypted using the same encryption method and key
    ///     that will be used for decryption.
    ///
    /// - Note: This initializer does not validate the encrypted data, so it's
    ///   important to ensure that the data is properly encrypted before using
    ///   this initializer.
    public init(
        id: UUID,
        data: Data
    ) {
        self.id = id
        self.data = data
    }

    /// Asynchronously decrypts the properties of the communication model.
    ///
    /// This method decrypts the stored encrypted data using the provided symmetric key
    /// and returns the unwrapped properties. If the key is incorrect or the data is
    /// corrupted, this method will throw an error.
    ///
    /// - Parameter symmetricKey: The symmetric key used for decryption. Must be the
    ///   same key that was used to encrypt the data originally.
    /// - Returns: The decrypted properties as `UnwrappedProps`.
    /// - Throws: `CryptoError.decryptionFailed` if decryption fails due to incorrect
    ///   key or corrupted data.
    ///
    /// - Note: This method performs the actual decryption operation and should be
    ///   used when you need to handle decryption errors explicitly. For a more
    ///   graceful approach, consider using `props(symmetricKey:)` instead.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }

    /// Asynchronously updates the properties of the communication model.
    ///
    /// This method encrypts the new properties using the provided symmetric key and
    /// updates the stored encrypted data. It then decrypts and returns the updated
    /// properties to confirm the update was successful.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption. This should be the
    ///     same key that was used to encrypt the original data.
    ///   - props: The new properties to be encrypted and stored. This object must
    ///     conform to both `Codable` and `Sendable` protocols.
    /// - Returns: The updated decrypted properties as `UnwrappedProps`, confirming
    ///   that the update was successful.
    /// - Throws: `CryptoError.encryptionFailed` if the encryption process fails.
    ///
    /// - Note: This method performs both encryption and decryption operations to
    ///   ensure that the update was successful. The returned properties can be
    ///   used to verify that the update was applied correctly.
    public func updateProps(symmetricKey: SymmetricKey, props: Codable & Sendable) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return try await decryptProps(symmetricKey: symmetricKey)
    }

    /// Creates a decrypted model of the specified type from the communication properties.
    ///
    /// This method decrypts the communication properties and creates an instance of
    /// the specified type using those properties. This is useful for converting the
    /// encrypted communication data into a specific model type for processing.
    ///
    /// - Parameters:
    ///   - of: The type of the model to create. This type must conform to both
    ///     `Sendable` and `Codable` protocols to ensure thread safety and serialization.
    ///   - symmetricKey: The symmetric key used for decryption. Must be the same
    ///     key that was used to encrypt the data originally.
    /// - Returns: An instance of the specified type populated with the decrypted properties.
    /// - Throws:
    ///   - `CryptoError.propsError` if the properties cannot be decrypted.
    ///   - A decoding error if the decrypted properties cannot be converted to the specified type.
    ///
    /// - Note: This method is currently hardcoded to return a `Communication` instance.
    ///   The generic parameter is included for future extensibility but is not
    ///   currently used in the implementation.
    public func makeDecryptedModel<T: Sendable & Codable>(of _: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return Communication(
            id: id,
            sharedId: props.sharedId,
            messageCount: props.messageCount,
            members: props.members,
            blockedMembers: props.blockedMembers,
            metadata: props.metadata,
            communicationType: props.communicationType
        ) as! T
    }
}

/// An enumeration representing the different types of message recipients in a messaging network.
///
/// This enumeration defines the various ways that messages can be addressed and routed
/// within the messaging system. Each case represents a different type of recipient
/// with specific routing and delivery characteristics.
///
/// - Note: This enumeration conforms to `Codable`, `Sendable`, and `Equatable` to support
///   serialization, thread safety, and comparison operations.
public enum MessageRecipient: Codable, Sendable, Equatable {
    /// A personal message intended for the user, visible across all their devices and to others on the network.
    ///
    /// This case represents messages that are sent directly to a specific user and are
    /// typically visible across all of that user's devices. These messages may also be
    /// visible to other users on the network depending on the system's privacy settings.
    case personalMessage

    /// A recipient identified by a nickname.
    ///
    /// This case is used when sending a message to a user identified by their chosen nickname.
    /// The nickname is stored as an associated value and is used for routing the message
    /// to the correct recipient.
    ///
    /// - Parameter String: The nickname of the intended recipient.
    case nickname(String)

    /// A recipient identified by a channel name.
    ///
    /// This case is used when sending a message to a specific channel where multiple users
    /// can participate. Channel messages are typically broadcast to all members of the
    /// specified channel.
    ///
    /// - Parameter String: The name of the channel where the message should be sent.
    case channel(String)

    /// A recipient for broadcast messages sent to multiple users.
    ///
    /// This case is used for messages intended to be sent to all users in the network
    /// or a specific group. Broadcast messages are typically used for system announcements,
    /// notifications, or general communications to a wide audience.
    case broadcast

    /// Computed property to derive the nickname string if applicable.
    ///
    /// This property extracts the nickname string from the `.nickname` case. It will
    /// cause a fatal error if called on any other case, so it should only be used
    /// when you are certain that the recipient is of type `.nickname`.
    ///
    /// - Returns: The nickname string associated with the `.nickname` case.
    /// - Warning: This property will cause a fatal error if called on any case other than `.nickname`.
    ///   Always check the case type before accessing this property.
    public var nicknameDescription: String {
        switch self {
        case let .nickname(name):
            name
        default:
            fatalError("Invalid Recipient Type")
        }
    }
}
