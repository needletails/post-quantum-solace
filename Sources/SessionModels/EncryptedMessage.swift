//
//  EncryptedMessage.swift
//  crypto-session
//
//  Created by Cole M on 4/18/25.
//
import Foundation
import DoubleRatchetKit
import NIOConcurrencyHelpers
import NeedleTailCrypto
import Crypto
import BSON

/// A structure representing an encrypted message in a communication system.
///
/// This struct encapsulates the details of an encrypted message, including its identifiers, communication base,
/// delivery state, and associated metadata.
///
/// ## Properties
/// - `id`: A unique identifier for the encrypted message, represented as a `UUID`.
/// - `base`: The base communication context in which the message is sent, represented as a `BaseCommunication`.
/// - `sendDate`: The date and time when the message was sent.
/// - `receiveDate`: An optional date and time when the message was received.
/// - `deliveryState`: The current delivery state of the message, represented as a `DeliveryState`.
/// - `message`: The encrypted message content, represented as a `CryptoMessage`.
/// - `sendersSecretName`: The secret name of the sender of the message.
/// - `sendersDeviceId`: The device ID of the sender, represented as a `UUID`.
///
/// ## Equatable Conformance
/// This struct conforms to the `Equatable` protocol, allowing for comparison of two `_EncryptedMessage` instances
/// based on their unique identifiers.
///
/// ## Initializer
/// - `init(id:base:sendDate:receiveDate:deliveryState:message:sendersSecretName:sendersDeviceId:)`: Initializes a new instance of `_EncryptedMessage` with the specified values.
public struct _EncryptedMessage: Sendable, Codable, Equatable {
    public let id: UUID
    public var base: BaseCommunication
    public let sendDate: Date
    public let receiveDate: Date?
    public var deliveryState: DeliveryState
    public var message: CryptoMessage
    public let sendersSecretName: String
    public let sendersDeviceId: UUID
    
    /// Compares two `_EncryptedMessage` instances for equality based on their unique identifiers.
    ///
    /// - Parameters:
    ///   - lhs: The left-hand side instance to compare.
    ///   - rhs: The right-hand side instance to compare.
    /// - Returns: A boolean indicating whether the two instances are equal.
    public static func == (lhs: _EncryptedMessage, rhs: _EncryptedMessage) -> Bool {
        return lhs.id == rhs.id
    }
}


/// A model representing an encrypted message and providing an interface for working with encrypted data.
///
/// This class allows for the creation of local models that can be saved to a database as encrypted data.
public final class EncryptedMessage: SecureModelProtocol, @unchecked Sendable, Hashable {
    
    /// The unique identifier for the message.
    public let id: UUID
    
    /// The unique identifier for the communication this message belongs to.
    public let communicationId: UUID
    
    /// The session context identifier associated with the message.
    public let sessionContextId: Int
    
    /// A shared identifier for the message.
    public let sharedId: String
    
    /// The sequence number of the message in the communication.
    public let sequenceNumber: Int
    
    /// The encrypted data of the message.
    public var data: Data
    
    private let lock = NIOLock()
    private let crypto = NeedleTailCrypto()
    
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id
        case communicationId = "a"
        case sessionContextId = "b"
        case sharedId = "c"
        case sequenceNumber = "d"
        case data = "e"
    }
    
    /// Asynchronously retrieves the decrypted properties of the message, if available.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: An optional `UnwrappedProps` containing the decrypted properties.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }
    
    /// A struct representing the unwrapped properties of the message.
    /// This includes details such as delivery state, timestamps, and message content.
    public struct UnwrappedProps: Codable, Sendable, CommunicationProtocol {
        /// The base object for all communication types.
        public var base: BaseCommunication
        
        /// The date and time when the message was sent.
        public let sendDate: Date
        
        /// The date and time when the message was received.
        public let receiveDate: Date?
        
        /// The current delivery state of the message.
        public var deliveryState: DeliveryState
        
        /// The content of the message.
        public var message: CryptoMessage
        
        /// The sender's secret name, which may be used for privacy.
        public let sendersSecretName: String
        
        /// The unique identifier for the sender's identity.
        public let sendersDeviceId: UUID
        
        // MARK: - Coding Keys
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case base = "a"
            case sendDate = "b"
            case receiveDate = "c"
            case deliveryState = "d"
            case message = "e"
            case sendersSecretName = "f"
            case sendersDeviceId = "g"
        }
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - base: The base communication object.
        ///   - sendDate: The date and time when the message was sent.
        ///   - receiveDate: The date and time when the message was received.
        ///   - deliveryState: The current delivery state of the message.
        ///   - message: The content of the message.
        ///   - sendersSecretName: The sender's secret name.
        ///   - sendersDeviceId: The unique identifier for the sender's identity.
        public init(
            base: BaseCommunication,
            sendDate: Date,
            receiveDate: Date? = nil,
            deliveryState: DeliveryState,
            message: CryptoMessage,
            sendersSecretName: String,
            sendersDeviceId: UUID
        ) {
            self.base = base
            self.sendDate = sendDate
            self.receiveDate = receiveDate
            self.deliveryState = deliveryState
            self.message = message
            self.sendersSecretName = sendersSecretName
            self.sendersDeviceId = sendersDeviceId
        }
    }
    
    /// Initializes a new `EncryptedMessage` instance.
    /// - Parameters:
    ///   - id: The unique identifier for the message.
    ///   - communicationId: The ID of the communication.
    ///   - sessionContextId: The session context identifier.
    ///   - sharedId: The shared identifier for the message.
    ///   - sequenceNumber: The sequence number of the message.
    ///   - props: The unwrapped properties of the message.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
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
    /// - Parameters:
    ///   - id: The unique identifier for the message.
    ///   - communicationId: The ID of the communication.
    ///   - sessionContextId: The session context identifier.
    ///   - sharedId: The shared identifier for the message.
    ///   - sequenceNumber: The sequence number of the message.
    ///   - data: The encrypted data of the message.
    /// - Throws: An error if the data is invalid.
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
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties of the message.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        lock.lock()
        defer {
            lock.unlock()
        }
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }
    
    /// Asynchronously updates the properties of the model using the provided symmetric key.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties.
    /// - Throws: An error if encryption fails.
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
    /// - Parameters:
    ///   - props: The new unwrapped properties to be set.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Returns: The updated `EncryptedMessage`.
    /// - Throws: An error if encryption fails.
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
    /// - Parameters:
    ///   - of: The type of the model to create.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An instance of the specified type containing the decrypted properties.
    /// - Throws: An error if decryption fails or if the properties cannot be cast to the specified type.
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return _EncryptedMessage(
            id: id,
            base: props.base,
            sendDate: props.sendDate,
            receiveDate: props.receiveDate,
            deliveryState: props.deliveryState,
            message: props.message,
            sendersSecretName: props.sendersSecretName,
            sendersDeviceId: props.sendersDeviceId) as! T
    }
    
    /// Asynchronously updates the metadata of the message properties using the provided symmetric key.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for decryption and encryption.
    ///   - metadata: The new metadata to be added.
    ///   - key: The key under which the metadata will be stored.
    /// - Returns: The updated decrypted properties.
    /// - Throws: An error if decryption or encryption fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.message.metadata[key] = metadata
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    /// Asynchronously updates the metadata of the message properties and returns the updated `EncryptedMessage`.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for decryption and encryption.
    ///   - metadata: The new metadata to be added.
    ///   - key: The key under which the metadata will be stored.
    /// - Returns: The updated `EncryptedMessage`.
    /// - Throws: An error if decryption or encryption fails.
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> EncryptedMessage {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        props.message.metadata[key] = metadata
        return try await updateMessage(with: props, symmetricKey: symmetricKey)
    }
    
    /// Compares two `EncryptedMessage` instances for equality.
    /// - Parameters:
    ///   - lhs: The first `EncryptedMessage` instance.
    ///   - rhs: The second `EncryptedMessage` instance.
    /// - Returns: A Boolean value indicating whether the two instances are equal.
    public static func == (lhs: EncryptedMessage, rhs: EncryptedMessage) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Computes the hash value for the `EncryptedMessage`.
    /// - Parameter hasher: The hasher to use for hashing.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

/// An enumeration representing the delivery state of a message in a communication.
public enum DeliveryState: Codable, Sendable, Equatable {
    /// The message has been successfully delivered to the recipient.
    case delivered
    
    /// The message has been read by the recipient.
    case read
    
    /// The message has been received by the recipient's device but not yet read.
    case received
    
    /// The message is currently waiting to be delivered (e.g., due to network issues).
    case waitingDelivery
    
    /// The message has not been sent or is in an undefined state.
    case none
    
    /// The message has been blocked from being delivered (e.g., by the recipient's settings).
    case blocked
    
    /// The message failed to be delivered due to an error (e.g., network failure).
    case failed(String)
    
    /// The message is in the process of being sent but has not yet been delivered.
    case sending
    
    /// The message has been scheduled for delivery at a later time.
    case scheduled(Date)
}

/// A struct representing a cryptographically secure message.
///
/// This struct contains the message content, metadata, recipient information, and additional properties related to the message.
public struct CryptoMessage: Codable, Sendable {
    /// The text content of the message.
    public var text: String
    
    /// Metadata associated with the message.
    public var metadata: Document
    
    /// The recipient of the message.
    public var recipient: MessageRecipient
    
    /// Transport information related to the message, if any.
    public var transportInfo: Data?
    
    /// The date and time when the message was sent.
    public let sentDate: Date
    
    /// The time interval after which the message should be destroyed, if applicable.
    public let destructionTime: TimeInterval?
    
    /// The date and time when the message was last updated.
    public var updatedDate: Date?
    
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
