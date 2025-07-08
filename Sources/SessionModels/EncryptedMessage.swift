//
//  EncryptedMessage.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/18/25.
//
import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import NeedleTailCrypto
import NIOConcurrencyHelpers

/// A model representing an encrypted message stored locally on a device.
///
/// This class provides an interface for working with encrypted message data that is persisted
/// to a local database. The actual message content is encrypted and stored in the `data` property,
/// while metadata like IDs and sequence numbers are stored in plain text for efficient querying.
///
/// ## Key Features
/// - **Local Storage**: Designed for device-local persistence, not network transmission
/// - **Encrypted Content**: Message payload is encrypted using symmetric encryption with BSON serialization
/// - **Thread-Safe**: Uses locks to ensure thread safety during encryption/decryption operations
/// - **Metadata Preservation**: Keeps essential metadata unencrypted for database operations
/// - **Concurrency Support**: Implements `@unchecked Sendable` for safe concurrent access
///
/// ## Security Considerations
/// - All sensitive message content is encrypted using the provided symmetric key
/// - Only metadata required for database operations remains unencrypted
/// - Thread-safe operations prevent race conditions during encryption/decryption
/// - Keys should be managed securely and not persisted alongside encrypted data
///
/// ## Usage
/// ```swift
/// // Create a new encrypted message
/// let message = try EncryptedMessage(
///     id: UUID(),
///     communicationId: commId,
///     sessionContextId: contextId,
///     sharedId: "shared-123",
///     sequenceNumber: 1,
///     props: messageProps,
///     symmetricKey: key
/// )
///
/// // Decrypt and access message content
/// if let decryptedProps = await message.props(symmetricKey: key) {
///     print(decryptedProps.message.text)
/// }
/// ```
///
/// ## Error Handling
/// The class throws `CryptoError` instances for encryption/decryption failures:
/// - `CryptoError.encryptionFailed`: When message encryption fails
/// - `CryptoError.decryptionFailed`: When message decryption fails
/// - `CryptoError.propsError`: When property access fails
public final class EncryptedMessage: SecureModelProtocol, @unchecked Sendable, Hashable {
    /// The unique identifier for the message.
    public let id: UUID

    /// The unique identifier for the communication this message belongs to.
    public let communicationId: UUID

    /// The session context identifier associated with the message.
    public let sessionContextId: Int

    /// A shared identifier for the message, typically used for grouping related messages.
    public let sharedId: String

    /// The sequence number of the message in the communication, used for ordering.
    public let sequenceNumber: Int

    /// The encrypted data of the message containing the serialized `UnwrappedProps`.
    public var data: Data

    /// Thread-safe lock for protecting encryption/decryption operations.
    private let lock = NIOLock()

    /// Cryptographic operations handler.
    private let crypto = NeedleTailCrypto()

    /// Coding keys for BSON serialization with obfuscated field names.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id
        case communicationId = "a"
        case sessionContextId = "b"
        case sharedId = "c"
        case sequenceNumber = "d"
        case data = "e"
    }

    /// Asynchronously retrieves the decrypted properties of the message.
    ///
    /// This method decrypts the encrypted message data and returns the structured properties
    /// containing the message content, metadata, and delivery information. The method is
    /// thread-safe and handles decryption errors gracefully by returning `nil`.
    ///
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted message properties, or `nil` if decryption fails or the data is corrupted.
    /// - Note: This method is thread-safe and may suspend the current task during decryption.
    /// - Important: The symmetric key must be the same one used for encryption.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    /// A struct representing the decrypted properties of an encrypted message.
    ///
    /// This struct contains all the message data that was encrypted and stored in the `EncryptedMessage.data`
    /// property. It includes the message content, delivery state, timestamps, and sender information.
    /// This is the primary interface for accessing message content after decryption.
    ///
    /// ## Properties
    /// - `id`: The unique identifier for the message
    /// - `base`: The base communication context this message belongs to
    /// - `sentDate`: When the message was sent
    /// - `receiveDate`: When the message was received (if applicable)
    /// - `deliveryState`: Current delivery status (sent, delivered, read, etc.)
    /// - `message`: The actual message content and metadata
    /// - `senderSecretName`: The sender's secret identifier for privacy
    /// - `senderDeviceId`: The sender's device identifier
    ///
    /// ## Thread Safety
    /// This struct is `Sendable` and can be safely passed between concurrent contexts.
    public struct UnwrappedProps: Codable, Sendable, CommunicationProtocol {
        /// The unique identifier for the message.
        public let id: UUID

        /// The base object for all communication types.
        public var base: BaseCommunication

        /// The date and time when the message was sent.
        public let sentDate: Date

        /// The date and time when the message was received, if applicable.
        public let receiveDate: Date?

        /// The current delivery state of the message.
        public var deliveryState: DeliveryState

        /// The content of the message including text, metadata, and recipient information.
        public var message: CryptoMessage

        /// The sender's secret name, which may be used for privacy and anonymity.
        public let senderSecretName: String

        /// The unique identifier for the sender's device identity.
        public let senderDeviceId: UUID

        /// Coding keys for BSON serialization with obfuscated field names.
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case id = "a"
            case base = "b"
            case sentDate = "c"
            case receiveDate = "d"
            case deliveryState = "e"
            case message = "f"
            case senderSecretName = "g"
            case senderDeviceId = "h"
        }

        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - id: The unique identifier for the message.
        ///   - base: The base communication object.
        ///   - sentDate: The date and time when the message was sent.
        ///   - receiveDate: The date and time when the message was received, optional.
        ///   - deliveryState: The current delivery state of the message.
        ///   - message: The content of the message.
        ///   - senderSecretName: The sender's secret name for privacy.
        ///   - senderDeviceId: The unique identifier for the sender's device identity.
        public init(
            id: UUID,
            base: BaseCommunication,
            sentDate: Date,
            receiveDate: Date? = nil,
            deliveryState: DeliveryState,
            message: CryptoMessage,
            senderSecretName: String,
            senderDeviceId: UUID
        ) {
            self.id = id
            self.base = base
            self.sentDate = sentDate
            self.receiveDate = receiveDate
            self.deliveryState = deliveryState
            self.message = message
            self.senderSecretName = senderSecretName
            self.senderDeviceId = senderDeviceId
        }
    }

    /// Initializes a new `EncryptedMessage` instance with properties to be encrypted.
    ///
    /// This initializer creates a new encrypted message by serializing the provided properties
    /// to BSON format and then encrypting them using the specified symmetric key.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the message.
    ///   - communicationId: The ID of the communication this message belongs to.
    ///   - sessionContextId: The session context identifier.
    ///   - sharedId: The shared identifier for the message.
    ///   - sequenceNumber: The sequence number of the message in the communication.
    ///   - props: The unwrapped properties of the message to be encrypted.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: `CryptoError.encryptionFailed` if encryption fails.
    public init(
        id: UUID,
        communicationId: UUID,
        sessionContextId: Int,
        sharedId: String,
        sequenceNumber: Int,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        self.communicationId = communicationId
        self.sessionContextId = sessionContextId
        self.sharedId = sharedId
        self.sequenceNumber = sequenceNumber

        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }

    /// Initializes a new `EncryptedMessage` instance with existing encrypted data.
    ///
    /// This initializer is typically used when loading encrypted messages from persistent storage.
    /// The encrypted data should have been created using the other initializer.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the message.
    ///   - communicationId: The ID of the communication this message belongs to.
    ///   - sessionContextId: The session context identifier.
    ///   - sharedId: The shared identifier for the message.
    ///   - sequenceNumber: The sequence number of the message in the communication.
    ///   - data: The pre-encrypted data of the message.
    /// - Throws: An error if the data is invalid or corrupted.
    public init(
        id: UUID,
        communicationId: UUID,
        sessionContextId: Int,
        sharedId: String,
        sequenceNumber: Int,
        data: Data
    ) throws {
        self.id = id
        self.communicationId = communicationId
        self.sessionContextId = sessionContextId
        self.sharedId = sharedId
        self.sequenceNumber = sequenceNumber
        self.data = data
    }

    /// Asynchronously decrypts the properties of the message using the provided symmetric key.
    ///
    /// This method performs the actual decryption operation in a thread-safe manner. It decrypts
    /// the BSON-serialized data and deserializes it back into `UnwrappedProps`.
    ///
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties of the message.
    /// - Throws: `CryptoError.decryptionFailed` if decryption fails.
    /// - Note: This method is thread-safe and uses locks to prevent concurrent access issues.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        lock.lock()
        defer {
            lock.unlock()
        }
        guard let decrypted = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }

    /// Asynchronously updates the properties of the model using the provided symmetric key.
    ///
    /// This method re-encrypts the message with new properties. It's thread-safe and handles
    /// the complete encryption cycle including BSON serialization.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties, or `nil` if the operation fails.
    /// - Throws: `CryptoError.encryptionFailed` if encryption fails.
    /// - Note: This method is thread-safe and uses locks to prevent concurrent access issues.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        lock.lock()
        do {
            let data = try BSONEncoder().encodeData(props)
            guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
                throw CryptoError.encryptionFailed
            }
            self.data = encryptedData
            lock.unlock()
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            lock.unlock()
            throw error
        }
    }

    /// Updates the message with new properties and returns the updated `EncryptedMessage`.
    ///
    /// This method re-encrypts the message with new properties and returns the updated instance.
    /// Unlike `updateProps`, this method returns the `EncryptedMessage` itself rather than the decrypted properties.
    ///
    /// - Parameters:
    ///   - props: The new unwrapped properties to be set.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Returns: The updated `EncryptedMessage` instance.
    /// - Throws: `CryptoError.encryptionFailed` if encryption fails.
    /// - Note: This method is thread-safe and uses locks to prevent concurrent access issues.
    public func updateMessage(with props: UnwrappedProps, symmetricKey: SymmetricKey) async throws -> EncryptedMessage {
        lock.lock()
        defer {
            lock.unlock()
        }
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return self
    }

    /// Creates a decrypted model of the specified type from the encrypted message.
    ///
    /// This method attempts to create a model of the specified generic type from the decrypted
    /// properties. It's primarily used for type conversion and casting operations.
    ///
    /// - Parameters:
    ///   - of: The type of the model to create.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type containing the decrypted properties.
    /// - Throws: `CryptoError.propsError` if decryption fails or if the properties cannot be cast to the specified type.
    /// - Warning: This method uses force casting (`as!`) which may crash if the type conversion fails.
    public func makeDecryptedModel<T: Sendable & Codable>(of _: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return EncryptedMessage.UnwrappedProps(
            id: id,
            base: props.base,
            sentDate: props.sentDate,
            receiveDate: props.receiveDate,
            deliveryState: props.deliveryState,
            message: props.message,
            senderSecretName: props.senderSecretName,
            senderDeviceId: props.senderDeviceId
        ) as! T
    }

    /// Asynchronously updates the metadata of the message properties using the provided symmetric key.
    ///
    /// This method allows updating specific metadata within the message without needing to
    /// reconstruct the entire `UnwrappedProps` object. It decrypts the current message,
    /// updates the specified metadata, and re-encrypts the message.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for decryption and encryption.
    ///   - metadata: The new metadata to be added.
    ///   - key: The key under which the metadata will be stored in the message's metadata dictionary.
    /// - Returns: The updated decrypted properties, or `nil` if the operation fails.
    /// - Throws: `CryptoError.decryptionFailed` or `CryptoError.encryptionFailed` if the operation fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.message.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }

    /// Asynchronously updates the metadata of the message properties and returns the updated `EncryptedMessage`.
    ///
    /// This method is similar to `updatePropsMetadata` but returns the updated `EncryptedMessage`
    /// instance rather than the decrypted properties.
    ///
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for decryption and encryption.
    ///   - metadata: The new metadata to be added.
    ///   - key: The key under which the metadata will be stored in the message's metadata dictionary.
    /// - Returns: The updated `EncryptedMessage` instance.
    /// - Throws: `CryptoError.decryptionFailed` or `CryptoError.encryptionFailed` if the operation fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> EncryptedMessage {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.message.metadata[key] = metadata
        return try await updateMessage(with: props, symmetricKey: symmetricKey)
    }

    /// Compares two `EncryptedMessage` instances for equality.
    ///
    /// Two `EncryptedMessage` instances are considered equal if they have the same `id`.
    /// This comparison does not consider the encrypted content or other properties.
    ///
    /// - Parameters:
    ///   - lhs: The first `EncryptedMessage` instance.
    ///   - rhs: The second `EncryptedMessage` instance.
    /// - Returns: A Boolean value indicating whether the two instances are equal.
    public static func == (lhs: EncryptedMessage, rhs: EncryptedMessage) -> Bool {
        lhs.id == rhs.id
    }

    /// Computes the hash value for the `EncryptedMessage`.
    ///
    /// The hash value is based solely on the message's `id` property.
    ///
    /// - Parameter hasher: The hasher to use for hashing.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

/// An enumeration representing the delivery state of a message in a communication.
///
/// This enum provides a comprehensive set of states that a message can be in during its
/// lifecycle from creation to final delivery confirmation.
public enum DeliveryState: Codable, Sendable, Equatable {
    /// The message has been successfully delivered to the recipient's device.
    case delivered

    /// The message has been read by the recipient.
    case read

    /// The message has been received by the recipient's device but not yet read.
    case received

    /// The message is currently waiting to be delivered (e.g., due to network issues or recipient unavailability).
    case waitingDelivery

    /// The message has not been sent or is in an undefined state.
    case none

    /// The message has been blocked from being delivered (e.g., by the recipient's privacy settings or spam filters).
    case blocked

    /// The message failed to be delivered due to an error (e.g., network failure, invalid recipient).
    case failed(String)

    /// The message is in the process of being sent but has not yet been delivered.
    case sending

    /// The message has been scheduled for delivery at a later time.
    case scheduled(Date)
}

/// A struct representing a cryptographically secure message.
///
/// This struct contains the message content, metadata, recipient information, and additional
/// properties related to the message. It's designed to be serialized and encrypted as part
/// of the `EncryptedMessage` data payload.
///
/// ## Security Features
/// - Supports self-destructing messages via `destructionTime`
/// - Includes transport information for secure delivery
/// - Maintains metadata for extensibility
/// - Tracks message lifecycle with timestamps
public struct CryptoMessage: Codable, Sendable {
    /// The text content of the message.
    public var text: String

    /// Metadata associated with the message, stored as a BSON document for flexibility.
    public var metadata: Document

    /// The recipient of the message.
    public var recipient: MessageRecipient

    /// Transport information related to the message, if any.
    /// This may include routing information, encryption parameters, or delivery instructions.
    public var transportInfo: Data?

    /// The date and time when the message was sent.
    public let sentDate: Date

    /// The time interval after which the message should be destroyed, if applicable.
    /// If set, the message should be automatically deleted after this interval.
    public let destructionTime: TimeInterval?

    /// The date and time when the message was last updated.
    public var updatedDate: Date?

    /// Coding keys for BSON serialization with obfuscated field names.
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case text = "a"
        case metadata = "b"
        case recipient = "c"
        case transportInfo = "d"
        case sentDate = "e"
        case destructionTime = "f"
        case updatedDate = "g"
    }

    /// Initializes a new instance of `CryptoMessage`.
    /// - Parameters:
    ///   - text: The text content of the message.
    ///   - metadata: Metadata associated with the message.
    ///   - recipient: The recipient of the message.
    ///   - transportInfo: Optional transport information related to the message.
    ///   - sentDate: The date and time when the message was sent.
    ///   - destructionTime: Optional time interval after which the message should be destroyed.
    ///   - updatedDate: Optional date and time when the message was last updated.
    public init(
        text: String,
        metadata: Document,
        recipient: MessageRecipient,
        transportInfo: Data? = nil,
        sentDate: Date,
        destructionTime: TimeInterval?,
        updatedDate: Date? = nil
    ) {
        self.text = text
        self.metadata = metadata
        self.recipient = recipient
        self.transportInfo = transportInfo
        self.sentDate = sentDate
        self.destructionTime = destructionTime
        self.updatedDate = updatedDate
    }
}
